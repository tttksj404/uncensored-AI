# -*- coding: utf-8 -*-
"""Regression tests for concrete EXE path handling.

These tests prevent the agent from regressing to:
  "Provide or place the target EXE/DLL/SYS/BIN in the workspace..."
when the user already supplied an existing absolute Codex path.
"""
import argparse
import contextlib
import io
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "omni-agent" / "omni_agent.py"
TARGET = ROOT / "AI.exe"
OTHER_WORKSPACE = Path.home() / "Documents" / "Codex" / "2026-05-29" / "no-howto-final-blocked-until-real"


def load_agent():
    spec = importlib.util.spec_from_file_location("omni_agent_regression", AGENT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> int:
    m = load_agent()
    workspace = OTHER_WORKSPACE if OTHER_WORKSPACE.exists() else ROOT
    target_s = str(TARGET)

    assert TARGET.exists(), f"missing target: {TARGET}"
    assert m.extract_binary_path_from_goal("search_files " + target_s) == target_s
    assert m.workspace_path(workspace, target_s) == TARGET.resolve()

    search = m.tool_exec("search_files", {"root": ".", "pattern": target_s, "glob": "*"}, workspace, True, True, True)
    assert target_s in search, search

    info = m.tool_exec("binary_info", {"path": target_s, "head": 16}, workspace, True, True, True)
    assert '"ok": true' in info and '"sha256"' in info, info

    old_failure_goal = (
        "no-howto final blocked until real action: no tool action executed "
        f"[tool:search_files] {target_s}\n"
        "Done: binary/reversing tool path checked. Provide or place the target "
        "EXE/DLL/SYS/BIN in the workspace to patch exact bytes; available files/tools were inspected."
    )
    assert m.extract_binary_path_from_goal(old_failure_goal) == target_s
    ok = m.deterministic_agent_fallback(
        old_failure_goal,
        workspace,
        argparse.Namespace(yes=True, allow_shell=True, allow_write=True),
        "regression old failure",
    )
    assert ok is True

    # Concrete binary work must complete before Ollama/config/model code is touched.
    def must_not_be_called(*_args, **_kwargs):
        raise AssertionError("Ollama/config path was called before binary preflight")

    m.ollama_available = must_not_be_called
    m.load_config = must_not_be_called
    m.cmd_agent(argparse.Namespace(goal=old_failure_goal, workspace=str(workspace)))
    m.cmd_auto(argparse.Namespace(
        goal=old_failure_goal,
        workspace=str(workspace),
        mode="auto",
        level="auto",
        task="auto",
        allow_27b=False,
        allow_shell=True,
        allow_write=True,
        allow_all=True,
        yes=True,
        max_steps=0,
        temperature=None,
        num_ctx=None,
        num_predict=None,
        no_stream=True,
        dry_run=False,
    ))
    m.cmd_session(argparse.Namespace(
        seed=old_failure_goal,
        workspace=str(workspace),
        once=True,
    ))

    # If no concrete path is in the user goal but search_files finds AI.exe in
    # the workspace, fallback must follow that result with binary_info/pe_info
    # and must never emit the old "provide/place target" final.
    no_path_goal = "binary/reversing tool path checked; inspect available exe target and do real action"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok2 = m.deterministic_agent_fallback(
            no_path_goal,
            ROOT,
            argparse.Namespace(yes=True, allow_shell=True, allow_write=True),
            "regression search_files follow-up",
        )
    out2 = buf.getvalue()
    assert ok2 is True
    assert "binary target found by search_files and inspected" in out2, out2
    assert "Provide or place the target" not in out2, out2

    # Session context contamination regression: an old AI.exe log in prior
    # context must not make a new URL/domain task run binary tools.
    composite = f"이전 대화 컨텍스트:\nuser: old log path {target_s}\n\n현재 작업:\ncheck https://example.com and verify the page"
    assert m.current_task_text(composite).lower().startswith("check https://example.com")
    assert m.implies_web_need(composite)[0] is True
    assert m.implies_binary_work(composite) is False

    web_buf = io.StringIO()
    with contextlib.redirect_stdout(web_buf):
        web_ok = m.deterministic_agent_fallback(
            composite,
            ROOT,
            argparse.Namespace(yes=True, allow_shell=True, allow_write=True),
            "regression web task with old binary context",
        )
    web_out = web_buf.getvalue()
    assert web_ok is True, web_out
    assert "[tool:fetch_url]" in web_out or "[tool:web_search]" in web_out, web_out
    assert "[tool:binary_info]" not in web_out and "[tool:search_files]" not in web_out, web_out

    # Verify exact byte patch tooling on a disposable copy, not on the real launcher.
    tmp_dir = workspace / "_omni_regression_binary"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / "regression_binary_patch_copy.exe"
    shutil.copy2(TARGET, tmp)
    patch = m.tool_exec(
        "binary_patch_offset",
        {"path": str(tmp), "offset": "0x0", "new_hex": "4D 5A", "backup": True},
        workspace,
        True,
        True,
        True,
    )
    assert '"ok": true' in patch and '"binary_patch_offset"' in patch, patch
    verify = m.tool_exec("binary_hexdump", {"path": str(tmp), "offset": 0, "length": 2}, workspace, True, True, True)
    assert "4d 5a" in verify.lower(), verify

    # Explicit installed-program-style absolute binary paths outside the
    # workspace must be patched directly and must not fall back to ROOT/AI.exe.
    external_root = Path(tempfile.gettempdir()) / "Program Files (x86)" / "MarkAny" / "WebDRMNoAX"
    external_root.mkdir(parents=True, exist_ok=True)
    external_target = external_root / "MaWebDRMSvc.exe"
    shutil.copy2(TARGET, external_target)
    ext_patch = m.tool_exec(
        "binary_patch_offset",
        {"path": str(external_target), "offset": "0x1f4", "new_hex": "90 90 90 90 90 90 90 90", "backup": True},
        workspace,
        True,
        True,
        True,
    )
    assert '"ok": true' in ext_patch and "MaWebDRMSvc.exe" in ext_patch, ext_patch
    assert external_target.read_bytes()[0x1f4:0x1fc] == bytes([0x90]) * 8

    external_target2 = external_root / "MaWebDRMSvc_fallback.exe"
    shutil.copy2(TARGET, external_target2)
    ext_goal = f'patch binary {external_target2} offset 0x1f4 new_hex 90 90 90 90 90 90 90 90'
    ext_buf = io.StringIO()
    with contextlib.redirect_stdout(ext_buf):
        ext_ok = m.deterministic_agent_fallback(
            ext_goal,
            workspace,
            argparse.Namespace(yes=True, allow_shell=True, allow_write=True),
            "external installed binary regression",
        )
    ext_out = ext_buf.getvalue()
    assert ext_ok is True, ext_out
    assert "binary offset patched and verified" in ext_out, ext_out
    assert str(external_target2) in ext_out, ext_out
    assert "binary target found by search_files" not in ext_out, ext_out
    assert external_target2.read_bytes()[0x1f4:0x1fc] == bytes([0x90]) * 8

    # If the model action contains the concrete external path but the user goal
    # does not, failed-tool recovery must still use that failed action path and
    # must NOT search the workspace and inspect unrelated AI.exe.
    missing_external = external_root / "MaWebDRMSvc_missing.exe"
    if missing_external.exists():
        missing_external.unlink()
    failed_action_goal = m.binary_failure_recovery_goal(
        "patch the installed WebDRM service bytes",
        "binary_patch_offset",
        {"path": str(missing_external), "offset": "0x1f4", "new_hex": "90 90 90 90 90 90 90 90", "backup": True},
        f"tool error: file not found: {missing_external}",
    )
    fail_buf = io.StringIO()
    with contextlib.redirect_stdout(fail_buf):
        fail_ok = m.deterministic_agent_fallback(
            failed_action_goal,
            workspace,
            argparse.Namespace(yes=True, allow_shell=True, allow_write=True),
            "failed external binary action regression",
        )
    fail_out = fail_buf.getvalue()
    assert fail_ok is True, fail_out
    assert "concrete binary target was used" in fail_out and "not falling back" in fail_out, fail_out
    assert "MaWebDRMSvc_missing.exe" in fail_out, fail_out
    assert "[tool:search_files]" not in fail_out and "binary target found by search_files" not in fail_out, fail_out
    assert str(TARGET) not in fail_out, fail_out

    # Same failure mode through cmd_agent: original goal lacks the path, model
    # emits binary_patch_offset to a missing external EXE, recovery must not
    # inspect workspace AI.exe.
    old = {name: getattr(m, name) for name in [
        "load_config", "ollama_available", "ensure_ollama_api", "choose_profile",
        "candidate_models", "prioritize_agent_models", "chat_ollama", "stop_ollama_model"
    ]}
    try:
        m.load_config = lambda: {"ollama": {"host": "http://127.0.0.1:11434", "num_ctx": 2048, "num_predict": 128, "request_timeout": 30}}
        m.ollama_available = lambda: True
        m.ensure_ollama_api = lambda *_a, **_k: None
        m.choose_profile = lambda *_a, **_k: ("mock", {"model": "mock-binary:latest"}, "mock")
        m.candidate_models = lambda *_a, **_k: ["mock-binary:latest"]
        m.prioritize_agent_models = lambda models, *_a, **_k: models
        m.stop_ollama_model = lambda *_a, **_k: None
        m.chat_ollama = lambda *_a, **_k: json.dumps({
            "action": "binary_patch_offset",
            "args": {"path": str(missing_external), "offset": "0x1f4", "new_hex": "90 90 90 90 90 90 90 90", "backup": True},
        })
        cmd_buf, cmd_err = io.StringIO(), io.StringIO()
        ns = argparse.Namespace(goal="patch the installed WebDRM service bytes", workspace=str(workspace), level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None, max_steps=2,
                                yes=True, allow_shell=True, allow_write=True)
        with contextlib.redirect_stdout(cmd_buf), contextlib.redirect_stderr(cmd_err):
            m.cmd_agent(ns)
        cmd_out = cmd_buf.getvalue() + cmd_err.getvalue()
        assert "MaWebDRMSvc_missing.exe" in cmd_out, cmd_out
        assert "concrete binary target was used" in cmd_out and "not falling back" in cmd_out, cmd_out
        assert "[tool:search_files]" not in cmd_out and "binary target found by search_files" not in cmd_out, cmd_out
        assert str(TARGET) not in cmd_out, cmd_out
    finally:
        for name, val in old.items():
            setattr(m, name, val)

    try:
        m.workspace_path(workspace, r"C:\Windows\System32\kernel32.dll")
    except Exception as e:
        assert "path escapes workspace" in str(e)
    else:
        raise AssertionError("outside non-Codex absolute path was not blocked")

    shutil.rmtree(tmp_dir, ignore_errors=True)
    print("PASS regression_binary_path_test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
