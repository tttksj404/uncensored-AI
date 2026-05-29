# -*- coding: utf-8 -*-
"""
AI.exe/omni_agent regression watchdog.
Runs fast, mostly mocked tests that catch the exact recurring failures:
- model timeout loops
- leftover llama-server blocking fallback
- invalid/missing action JSON
- create_file/file_path alias mismatch
- deterministic local fallback when all models time out
- auto max_steps extension related control flow
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import socket

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "omni-agent" / "omni_agent.py"
REPORT = ROOT / "omni-agent" / "watchdog_test_report.json"


def load_agent():
    spec = importlib.util.spec_from_file_location("omni_agent_watchdog_target", AGENT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def run_ps(script: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def repair_stale_llama_servers() -> dict:
    """Kill orphan llama-server.exe only when no current AI/agent python is alive."""
    if os.name != "nt":
        return {"skipped": "non-windows"}
    ps = r'''
$result = [ordered]@{ ai_count = 0; llama_count = 0; killed = @(); mode = 'cim' }
try {
  $ai = Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
    ($_.Name -eq 'AI.exe') -or
    ($_.Name -eq 'python.exe' -and $_.CommandLine -like '*uncensored-heretic-ai-pc*omni_agent.py*')
  }
  $llama = Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -eq 'llama-server.exe' }
  $result.ai_count = @($ai).Count
  $result.llama_count = @($llama).Count
  if(@($ai).Count -eq 0){
    foreach($p in $llama){
      try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $result.killed += $p.ProcessId } catch {}
    }
  }
} catch {
  $result.mode = 'get-process-fallback'
  $ai = @(Get-Process -Name AI -ErrorAction SilentlyContinue)
  $py = @(Get-Process -Name python -ErrorAction SilentlyContinue)
  $llama = @(Get-Process -Name 'llama-server' -ErrorAction SilentlyContinue)
  $result.ai_count = @($ai).Count + @($py).Count
  $result.llama_count = @($llama).Count
  if((@($ai).Count + @($py).Count) -eq 0){
    foreach($p in $llama){
      try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; $result.killed += $p.Id } catch {}
    }
  }
}
$result | ConvertTo-Json -Compress
'''
    p = run_ps(ps)
    try:
        return json.loads(p.stdout.strip() or "{}")
    except Exception:
        return {"raw": p.stdout, "returncode": p.returncode}


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_compile():
    py_compile.compile(str(AGENT), doraise=True)


def test_timeout_classifier(oa):
    assert_true(oa.is_timeout_error(TimeoutError("timed out")), "TimeoutError not detected")
    assert_true(oa.is_timeout_error(socket.timeout("timed out")), "socket.timeout not detected")
    assert_true(oa.is_timeout_error(urllib.error.URLError(TimeoutError("timed out"))), "wrapped URLError timeout not detected")
    assert_true(not oa.is_timeout_error(RuntimeError("other")), "false positive timeout")


def test_action_normalization(oa):
    cases = [
        ({"action": "create_file", "file_path": "a.txt", "content": "OK"}, "write_file", "a.txt"),
        ({"tool": "browser.open", "args": {"url": "https://example.com"}}, "browser_open", None),
        ({"answer": "done"}, "final", None),
        ({"tool_calls": [{"function": {"name": "writefile", "arguments": "{\"path\":\"b.txt\",\"content\":\"B\"}"}}]}, "write_file", "b.txt"),
    ]
    for obj, want_action, want_path in cases:
        action, args = oa.normalize_agent_action(obj)
        assert_true(action == want_action, f"action normalize failed: {obj} -> {action}")
        if want_path:
            assert_true(args.get("path") == want_path, f"path normalize failed: {args}")


def test_goal_persistence_suffix(oa):
    original = oa.read_persistent_goal()
    token = "WATCHDOG_GOAL_PERSIST_OK"
    try:
        oa.write_persistent_goal(token)
        assert_true(oa.read_persistent_goal() == token, "persistent goal roundtrip failed")
        suffix = oa.goal_system_suffix()
        assert_true(token in suffix, f"persistent goal missing from suffix: {suffix!r}")
        assert_true("invalid JSON" in suffix and "verify completion before final" in suffix, f"goal suffix lost hardening text: {suffix!r}")
    finally:
        if original:
            oa.write_persistent_goal(original)
        else:
            with contextlib.suppress(Exception):
                oa.GOAL_PATH.unlink()


def test_missing_action_guard(oa):
    with tempfile.TemporaryDirectory() as td:
        out = oa.tool_exec("", {}, Path(td), True, True, True)
        assert_true("missing action" in out.lower(), f"missing action guard failed: {out}")


def test_session_auto_agent_file_edit_guard(oa):
    auto, reason = oa.should_session_auto_agent("sample.py에서 OLD를 NEW로 바꿔놔")
    assert_true(auto is True, f"session auto-agent missed concrete file edit: {reason}")


def test_model_order(oa):
    old = oa.ollama_tags
    try:
        oa.ollama_tags = lambda host: [
            "fast-gemma:latest", "fast-qwen:latest", "gemma4:latest",
            "hf.co/pegasus912/gemma-4-31B-it-heretic-Q4_K_M-GGUF:Q4_K_M",
        ]
        got = oa.prioritize_agent_models(["hf.co/pegasus912/gemma-4-31B-it-heretic-Q4_K_M-GGUF:Q4_K_M"], "x")[:4]
        want = ["fast-gemma:latest", "fast-qwen:latest", "gemma4:latest", "hf.co/pegasus912/gemma-4-31B-it-heretic-Q4_K_M-GGUF:Q4_K_M"]
        assert_true(got == want, f"bad model order: {got}")
    finally:
        oa.ollama_tags = old


def test_deterministic_fallback_write(oa):
    goal = "result.txt 파일을 만들고 내용은 WATCHDOG_OK 한 줄만 쓰고 final"
    with tempfile.TemporaryDirectory() as td:
        ns = argparse.Namespace(yes=True, allow_shell=True, allow_write=True)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            ok = oa.deterministic_agent_fallback(goal, Path(td), ns, "timeout")
        target = Path(td) / "result.txt"
        assert_true(ok, "deterministic fallback did not run")
        assert_true(target.exists(), "fallback did not create file")
        assert_true(target.read_text(encoding="utf-8").strip() == "WATCHDOG_OK", "fallback wrote wrong content")


def test_timeout_cmd_agent_fallback(oa):
    goal = "result.txt 파일을 만들고 내용은 WATCHDOG_TIMEOUT_OK 한 줄만 쓰고 final"
    old = {name: getattr(oa, name) for name in [
        "load_config", "ollama_available", "ensure_ollama_api", "choose_profile", "candidate_models",
        "prioritize_agent_models", "stop_ollama_model", "chat_ollama"
    ]}
    calls, stops = [], []
    try:
        oa.load_config = lambda: {"ollama": {"host": "http://127.0.0.1:11434", "num_ctx": 8192, "num_predict": 512, "request_timeout": 180}}
        oa.ollama_available = lambda: True
        oa.ensure_ollama_api = lambda host: None
        oa.choose_profile = lambda config, goal, level, task, allow_27b: ("test", {"model": "slow:latest"}, "unit")
        oa.candidate_models = lambda prof, host, dry_run=False: ["slow:latest", "slow2:latest", "slow3:latest"]
        oa.prioritize_agent_models = lambda models, host: models
        oa.stop_ollama_model = lambda model, host: stops.append(model)
        def fake_chat(config, model, *args, **kwargs):
            calls.append(model)
            raise TimeoutError("timed out")
        oa.chat_ollama = fake_chat
        with tempfile.TemporaryDirectory() as td:
            ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                    dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                    max_steps=2, yes=True, allow_shell=True, allow_write=True)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                oa.cmd_agent(ns)
            assert_true(calls == ["slow:latest", "slow2:latest"], f"timeout fallback not capped: {calls}")
            assert_true(stops == ["slow:latest", "slow2:latest"], f"timed-out models not stopped: {stops}")
            content = (Path(td) / "result.txt").read_text(encoding="utf-8").strip()
            assert_true(content == "WATCHDOG_TIMEOUT_OK", f"wrong deterministic content: {content}")
    finally:
        for name, val in old.items():
            setattr(oa, name, val)


def test_workspace_path_maps_container_and_blocks_escape(oa):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td).resolve()
        mapped = oa.workspace_path(root, "/workspace/nested/file.txt")
        assert_true(mapped == (root / "nested" / "file.txt").resolve(), f"/workspace path not mapped into workspace: {mapped}")
        mapped2 = oa.workspace_path(root, "C:/workspace/other.txt")
        assert_true(mapped2 == (root / "other.txt").resolve(), f"C:/workspace path not mapped into workspace: {mapped2}")
        try:
            oa.workspace_path(root, "C:/outside/file.txt")
        except ValueError:
            pass
        else:
            raise AssertionError("absolute path outside workspace was not blocked")


def test_blocked_final_switches_model(oa):
    goal = "create result.txt with content ANSWER_GUARD_OK one line then final"
    old = {name: getattr(oa, name) for name in [
        "load_config", "ollama_available", "ensure_ollama_api", "choose_profile", "candidate_models",
        "prioritize_agent_models", "chat_ollama"
    ]}
    calls = []
    m2_step = {"n": 0}
    try:
        oa.load_config = lambda: {"ollama": {"host": "http://127.0.0.1:11434", "num_ctx": 8192, "num_predict": 512, "request_timeout": 180}}
        oa.ollama_available = lambda: True
        oa.ensure_ollama_api = lambda host: None
        oa.choose_profile = lambda config, goal, level, task, allow_27b: ("test", {"model": "bad-final:latest"}, "unit")
        oa.candidate_models = lambda prof, host, dry_run=False: ["bad-final:latest", "good-tools:latest"]
        oa.prioritize_agent_models = lambda models, host: models
        def fake_chat(config, model, *args, **kwargs):
            calls.append(model)
            if model == "bad-final:latest":
                return json.dumps({"answer": "cannot proceed because no execution result is available"}, ensure_ascii=False)
            m2_step["n"] += 1
            if m2_step["n"] == 1:
                return json.dumps({"action": "write_file", "args": {"path": "result.txt", "content": "ANSWER_GUARD_OK\n"}}, ensure_ascii=False)
            if m2_step["n"] == 2:
                return json.dumps({"action": "read_file", "args": {"path": "result.txt"}}, ensure_ascii=False)
            return json.dumps({"action": "final", "args": {"answer": "wrote and verified result.txt"}}, ensure_ascii=False)
        oa.chat_ollama = fake_chat
        with tempfile.TemporaryDirectory() as td:
            ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                    dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                    max_steps=6, yes=True, allow_shell=True, allow_write=True)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                oa.cmd_agent(ns)
            content = (Path(td) / "result.txt").read_text(encoding="utf-8").strip()
            assert_true(content == "ANSWER_GUARD_OK", f"blocked-final recovery wrote wrong content: {content}")
            assert_true(calls[:2] == ["bad-final:latest", "bad-final:latest"], f"bad final retry count was reset/changed: {calls}")
            assert_true("good-tools:latest" in calls, f"did not switch away from blocked final model: {calls}")
    finally:
        for name, val in old.items():
            setattr(oa, name, val)


@contextlib.contextmanager
def mocked_agent_runtime(oa, models, fake_chat):
    old = {name: getattr(oa, name) for name in [
        "load_config", "ollama_available", "ensure_ollama_api", "choose_profile", "candidate_models",
        "prioritize_agent_models", "chat_ollama"
    ]}
    try:
        oa.load_config = lambda: {"ollama": {"host": "http://127.0.0.1:11434", "num_ctx": 8192, "num_predict": 512, "request_timeout": 180}}
        oa.ollama_available = lambda: True
        oa.ensure_ollama_api = lambda host: None
        oa.choose_profile = lambda config, goal, level, task, allow_27b: ("test", {"model": models[0]}, "unit")
        oa.candidate_models = lambda prof, host, dry_run=False: list(models)
        oa.prioritize_agent_models = lambda incoming, host: list(incoming)
        oa.chat_ollama = fake_chat
        yield
    finally:
        for name, val in old.items():
            setattr(oa, name, val)


def test_code_edit_line_regex_patch_tools(oa):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        f = root / "code.py"
        f.write_text("a=1\nb=2\nc=3\n", encoding="utf-8")
        info = json.loads(oa.tool_exec("file_info", {"path": "code.py"}, root, True, True, True))
        assert_true(info.get("ok") and info.get("lines") == 3 and "sha256" in info, f"file_info bad: {info}")
        part = oa.tool_exec("read_lines", {"path": "code.py", "start": 2, "end": 3}, root, True, True, True)
        assert_true("2: b=2" in part and "3: c=3" in part, f"read_lines bad: {part}")
        out = oa.tool_exec("replace_lines", {"path": "code.py", "start": 2, "end": 2, "content": "b=20", "backup": True}, root, True, True, True)
        assert_true(out.startswith("ok: replace_lines"), f"replace_lines failed: {out}")
        out = oa.tool_exec("insert_lines", {"path": "code.py", "line": 3, "where": "before", "content": "x=99", "backup": True}, root, True, True, True)
        assert_true(out.startswith("ok: insert_lines"), f"insert_lines failed: {out}")
        out = oa.tool_exec("delete_lines", {"path": "code.py", "start": 1, "end": 1, "backup": True}, root, True, True, True)
        assert_true(out.startswith("ok: delete_lines"), f"delete_lines failed: {out}")
        out = oa.tool_exec("regex_replace", {"path": "code.py", "pattern": "c=(\\d+)", "replacement": "c=30", "backup": True}, root, True, True, True)
        assert_true(out.startswith("ok: regex_replace"), f"regex_replace failed: {out}")
        text = f.read_text(encoding="utf-8")
        assert_true("b=20" in text and "x=99" in text and "c=30" in text and "a=1" not in text, f"line/regex tools wrong content: {text}")
        patch = "--- a/code.py\n+++ b/code.py\n@@ -1,3 +1,3 @@\n b=20\n-x=99\n+x=100\n c=30\n"
        out = oa.tool_exec("apply_unified_patch", {"patch": patch, "backup": True}, root, True, True, True)
        j = json.loads(out)
        assert_true(j.get("ok") and j.get("changed"), f"apply_unified_patch failed: {out}")
        assert_true("x=100" in f.read_text(encoding="utf-8"), "apply_unified_patch did not modify file")
        assert_true(list(root.glob("code.py.bak_*")), "code tools did not create backups")


def test_replace_in_file_tool(oa):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        f = root / "sample.py"
        f.write_text("VALUE = 'OLD'\nprint(VALUE)\n", encoding="utf-8")
        out = oa.tool_exec("replace_in_file", {"path": "sample.py", "old": "OLD", "new": "NEW", "backup": True}, root, True, True, True)
        text = f.read_text(encoding="utf-8")
        assert_true(out.startswith("ok: replace_in_file"), f"replace_in_file failed: {out}")
        assert_true("NEW" in text and "OLD" not in text, f"replace_in_file content wrong: {text}")
        assert_true(list(root.glob("sample.py.bak_*")), "replace_in_file did not create backup")


def test_binary_info_and_replace_tools(oa):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        f = root / "dummy.dll"
        f.write_bytes(b"MZ\x00\x00HELLO_OLD_DLL\x00END")
        info1 = oa.tool_exec("binary_info", {"path": "dummy.dll", "head": 16}, root, True, True, True)
        j1 = json.loads(info1)
        assert_true(j1.get("ok") and j1.get("size") == f.stat().st_size and "sha256" in j1, f"binary_info bad: {info1}")
        out = oa.tool_exec("binary_replace", {"path": "dummy.dll", "old_text": "OLD", "new_text": "NEW", "count": 1, "backup": True}, root, True, True, True)
        j2 = json.loads(out)
        data = f.read_bytes()
        assert_true(j2.get("ok") and j2.get("replacements") == 1, f"binary_replace failed: {out}")
        assert_true(b"HELLO_NEW_DLL" in data and b"HELLO_OLD_DLL" not in data, f"binary_replace content wrong: {data!r}")
        assert_true(list(root.glob("dummy.dll.bak_*")), "binary_replace did not create backup")
        bad = oa.tool_exec("binary_replace", {"path": "dummy.dll", "old_text": "NEW", "new_text": "LONGER", "count": 1}, root, True, True, True)
        assert_true(bad.startswith("tool error: binary_replace length mismatch"), f"binary_replace length guard failed: {bad}")


def test_reverse_binary_analysis_tools(oa):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        f = root / "mini.bin"
        data = bytearray(0x420)
        data[:2] = b"MZ"
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        data[0x80:0x84] = b"PE\x00\x00"
        coff = 0x84
        data[coff:coff + 2] = (0x8664).to_bytes(2, "little")
        data[coff + 2:coff + 4] = (1).to_bytes(2, "little")
        data[coff + 16:coff + 18] = (0xF0).to_bytes(2, "little")
        data[coff + 18:coff + 20] = (0).to_bytes(2, "little")
        opt = coff + 20
        data[opt:opt + 2] = (0x20B).to_bytes(2, "little")
        data[opt + 16:opt + 20] = (0x1000).to_bytes(4, "little")
        data[opt + 24:opt + 32] = (0x140000000).to_bytes(8, "little")
        data[opt + 84:opt + 86] = (3).to_bytes(2, "little")
        sec = opt + 0xF0
        data[sec:sec + 8] = b".text\x00\x00\x00"
        data[sec + 8:sec + 12] = (0x200).to_bytes(4, "little")
        data[sec + 12:sec + 16] = (0x1000).to_bytes(4, "little")
        data[sec + 16:sec + 20] = (0x200).to_bytes(4, "little")
        data[sec + 20:sec + 24] = (0x200).to_bytes(4, "little")
        data[sec + 36:sec + 40] = (0).to_bytes(4, "little")
        pe = oa.parse_pe_info(bytes(data))
        assert_true(pe.get("ok") and pe.get("machine") == "x64" and pe.get("entrypoint_rva") == "0x1000", f"pe_info failed: {pe}")
        f.write_bytes(b"MZ\x00\x00HELLO_BINARY_TOOL\x00END")
        hashes = json.loads(oa.tool_exec("file_hashes", {"path": "mini.bin"}, root, True, True, True))
        ftype = json.loads(oa.tool_exec("file_type", {"path": "mini.bin"}, root, True, True, True))
        assert_true(hashes.get("crc32") and hashes.get("sha512") and ftype.get("magic").startswith("PE/MZ"), f"file hash/type failed: {hashes} {ftype}")
        pe_tool = json.loads(oa.tool_exec("pe_info", {"path": "mini.bin"}, root, True, True, True))
        assert_true("sha256" in pe_tool and pe_tool.get("path", "").endswith("mini.bin"), f"pe_info tool did not return JSON: {pe_tool}")
        strings = json.loads(oa.tool_exec("binary_strings", {"path": "mini.bin", "limit": 20}, root, True, True, True))
        assert_true(any(s.get("text") == "HELLO_BINARY_TOOL" for s in strings.get("strings", [])), f"binary_strings missed marker: {strings}")
        dump = oa.tool_exec("binary_hexdump", {"path": "mini.bin", "offset": 0, "length": 16}, root, True, True, True)
        assert_true("00000000" in dump and "4d 5a" in dump, f"binary_hexdump bad: {dump}")
        search = json.loads(oa.tool_exec("binary_search", {"path": "mini.bin", "needle_text": "HELLO_BINARY_TOOL"}, root, True, True, True))
        assert_true(search.get("count") == 1 and search.get("offsets"), f"binary_search failed: {search}")
        pat = json.loads(oa.tool_exec("binary_pattern_search", {"path": "mini.bin", "pattern": "48 45 ?? 4c 4f"}, root, True, True, True))
        assert_true(pat.get("count") == 1 and pat.get("offsets") == search.get("offsets"), f"binary_pattern_search failed: {pat}")
        ent = json.loads(oa.tool_exec("binary_entropy", {"path": "mini.bin", "window": 256, "limit": 3}, root, True, True, True))
        assert_true(ent.get("ok") and "top" in ent, f"binary_entropy failed: {ent}")
        imp = json.loads(oa.tool_exec("pe_imports", {"path": "mini.bin"}, root, True, True, True))
        exp = json.loads(oa.tool_exec("pe_exports", {"path": "mini.bin"}, root, True, True, True))
        assert_true("ok" in imp and "ok" in exp, f"pe import/export failed: {imp} {exp}")
        ext = json.loads(oa.tool_exec("binary_extract", {"path": "mini.bin", "offset": 0, "length": 4, "out": "chunk.bin"}, root, True, True, True))
        assert_true(ext.get("ok") and (root / "chunk.bin").read_bytes() == b"MZ\x00\x00", f"binary_extract failed: {ext}")
        other = root / "other.bin"
        other.write_bytes(f.read_bytes().replace(b"HELLO", b"YELLO", 1))
        diff = json.loads(oa.tool_exec("binary_diff", {"path": "mini.bin", "other": "other.bin"}, root, True, True, True))
        assert_true(diff.get("range_count", 0) >= 1, f"binary_diff failed: {diff}")
        patched = json.loads(oa.tool_exec("binary_patch_offset", {"path": "mini.bin", "offset": search["offsets"][0], "new_text": "HELLO_BINARY_TOOL", "backup": True}, root, True, True, True))
        assert_true(patched.get("ok") and list(root.glob("mini.bin.bak_*")), f"binary_patch_offset failed: {patched}")
        p2 = root / "edit.bin"
        p2.write_bytes(b"ABCDEFGH")
        fill = json.loads(oa.tool_exec("binary_fill", {"path": "edit.bin", "offset": 2, "length": 2, "fill_text": "Z", "backup": True}, root, True, True, True))
        ins = json.loads(oa.tool_exec("binary_insert", {"path": "edit.bin", "offset": 4, "data_text": "II", "backup": True}, root, True, True, True))
        dele = json.loads(oa.tool_exec("binary_delete", {"path": "edit.bin", "offset": 4, "length": 2, "backup": True}, root, True, True, True))
        app = json.loads(oa.tool_exec("binary_append", {"path": "edit.bin", "data_text": "++", "backup": True}, root, True, True, True))
        assert_true(fill.get("ok") and ins.get("ok") and dele.get("ok") and app.get("ok") and p2.read_bytes() == b"ABZZEFGH++", f"binary edit tools failed: {p2.read_bytes()!r}")
        pp = json.loads(oa.tool_exec("binary_pattern_patch", {"path": "edit.bin", "pattern": "41 42 ?? ??", "new_text": "AB12", "backup": True}, root, True, True, True))
        assert_true(pp.get("ok") and p2.read_bytes().startswith(b"AB12"), f"binary_pattern_patch failed: {pp} {p2.read_bytes()!r}")
        rva = json.loads(oa.tool_exec("pe_rva_to_offset", {"path": "mini.bin", "rva": "0x1000"}, root, True, True, True))
        off2rva = json.loads(oa.tool_exec("pe_offset_to_rva", {"path": "mini.bin", "offset": "0x0"}, root, True, True, True))
        assert_true("ok" in rva and "ok" in off2rva, f"pe address mapping failed: {rva} {off2rva}")
        inv = json.loads(oa.tool_exec("re_tool_inventory", {}, root, True, True, True))
        assert_true(inv.get("ok") and "tools" in inv, f"re_tool_inventory failed: {inv}")
        action, args = oa.normalize_agent_action({"action": "disasm", "path": "mini.bin"})
        assert_true(action == "disassemble" and args.get("path") == "mini.bin", f"disasm alias failed: {action} {args}")
        action, args = oa.normalize_agent_action({"action": "patch_offset", "path": "mini.bin", "offset": "0x0", "new_hex": "4d 5a"})
        assert_true(action == "binary_patch_offset" and args.get("offset") == "0x0", f"patch_offset alias failed: {action} {args}")
        action, args = oa.normalize_agent_action({"action": "binary patch offset", "args": {"path": "mini.bin", "offset": "0x0", "new_content": "4d 5a"}})
        assert_true(action == "binary_patch_offset" and args.get("new_hex") == "4d 5a", f"spaced binary patch alias failed: {action} {args}")
        action, args = oa.normalize_agent_action({"action": "pattern_patch", "path": "mini.bin", "pattern": "4d 5a", "new_hex": "4d 5a"})
        assert_true(action == "binary_pattern_patch", f"pattern_patch alias failed: {action} {args}")
        refused, why = oa.is_refusal_or_howto_instead_of_action(
            "저는 인공지능 모델이기 때문에 저수준 바이너리 역공학은 물리적으로 불가능합니다.",
            "mini.bin를 열어보고 로직 파악해줘",
        )
        assert_true(refused and why, "reverse-engineering refusal was not blocked")


def test_binary_refusal_routes_to_real_patch_fallback(oa):
    goal = "sample.bin 바이너리 패치해줘"
    ok_answer = "역공학 도구로 분석했고 바이너리 패치 검증 완료"
    bad_answer = "직접적인 바이너리 패치가 불가능합니다"
    assert_true(
        oa.final_without_evidence(ok_answer, goal, ["binary_patch_offset", "binary_hexdump", "file_hashes"]) == (False, ""),
        "legitimate reverse/binary completion text was falsely blocked",
    )
    blocked, why = oa.final_without_evidence(bad_answer, goal, ["binary_patch_offset"])
    assert_true(blocked and "불가능" in why, f"binary refusal was not blocked: {blocked} {why}")

    ns = argparse.Namespace(yes=True, allow_shell=True, allow_write=True)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            (root / "sample.bin").write_bytes(bytes.fromhex("AA BB CC DD EE FF"))
            ok = oa.deterministic_agent_fallback("sample.bin offset 0x2 -> 90 90 바이너리 패치해줘", root, ns, "refusal")
            assert_true(ok and (root / "sample.bin").read_bytes() == bytes.fromhex("AA BB 90 90 EE FF"), "offset patch fallback failed")

            (root / "replace.bin").write_bytes(bytes.fromhex("11 22 33 44 55"))
            ok = oa.deterministic_agent_fallback("replace.bin replace 22 33 with 90 90 바이너리 패치해줘", root, ns, "refusal")
            assert_true(ok and (root / "replace.bin").read_bytes() == bytes.fromhex("11 90 90 44 55"), "replace patch fallback failed")

            (root / "pattern.bin").write_bytes(bytes.fromhex("01 48 8B 12 34 02"))
            ok = oa.deterministic_agent_fallback("pattern.bin pattern 48 8B ?? ?? -> 90 90 90 90 바이너리 패치해줘", root, ns, "refusal")
            assert_true(ok and (root / "pattern.bin").read_bytes() == bytes.fromhex("01 90 90 90 90 02"), "pattern patch fallback failed")


def test_web_search_fallback_and_refusal_patterns(oa):
    calls = []
    orig_http = oa.http_get_text
    try:
        def fake_http(url, max_bytes=500000):
            calls.append(url)
            if "bing.com" in url:
                return ('<html><li class="b_algo"><h2><a href="https://example.com/a">Example Result</a></h2></li></html>', "text/html")
            return ("<html><body>no result links here</body></html>", "text/html")
        oa.http_get_text = fake_http
        out = oa.web_search_duckduckgo("fallback search test", 3)
        assert_true("Example Result" in out and "https://example.com/a" in out and any("bing.com" in c for c in calls), f"web_search fallback failed: {out} calls={calls}")
    finally:
        oa.http_get_text = orig_http

    for answer in [
        "실행 프로그램 수정 불가: 저는 기본적으로 외부 프로그램을 다운로드하거나 실행할 권한이 없습니다.",
        "파일 시스템 접근 제한 때문에 제 기능 범위로는 이러한 종류의 문제를 해결할 수 없습니다.",
        "현재 상황에서는 다른 방법을 모색해야 하며 어떤 운영체제를 사용하고 계신가요?",
    ]:
        refused, why = oa.is_refusal_or_howto_instead_of_action(answer, "test.exe 바이너리 패치해줘")
        assert_true(refused and why, f"refusal variant not blocked: {answer}")
    web_needed, _ = oa.implies_web_need("실행 프로그램 수정 가능 도구 확인해줘")
    assert_true(not web_needed, "generic 확인 should not force web_search")
    mode, reason = oa.decide_mode("실행 프로그램 수정하고 바이너리 패치 가능한지 도구 확인해줘")
    assert_true(mode == "agent" and "binary" in reason, f"binary tool check should route to agent, got {mode} {reason}")


def test_resolve_tool_skips_permission_denied_dirs(oa):
    class DeniedRoot:
        name = "Scripts"
        def exists(self):
            raise PermissionError("denied")

    orig_tool_search_dirs = oa.tool_search_dirs
    orig_which = oa.shutil.which
    try:
        oa.tool_search_dirs = lambda: [DeniedRoot()]
        oa.shutil.which = lambda name: None
        out = oa.tool_exec("re_tool_inventory", {}, Path.cwd(), True, True, True)
        inv = json.loads(out)
        assert_true(inv.get("ok") is True and "tools" in inv, f"re_tool_inventory should survive denied dir: {out}")
    finally:
        oa.tool_search_dirs = orig_tool_search_dirs
        oa.shutil.which = orig_which


def test_preflight_does_not_intercept_broad_agent_jobs(oa):
    assert_true(oa.simple_local_preflight_allowed("create direct_auto.txt containing DIRECT-AUTO only"), "simple explicit create should allow preflight")
    assert_true(not oa.simple_local_preflight_allowed("?? ?? ?? ???? ?? ???"), "broad analysis/list job must not be preflighted")
    assert_true(not oa.simple_local_preflight_allowed("sample.py ??? ???? ?? ??? ??"), "test/fix job must remain in agent loop")
    assert_true(not oa.simple_local_preflight_allowed("create report.txt then inspect project and keep working"), "continuing multi-step job must remain in agent loop")


def test_forced_permissions_even_when_args_false(oa):
    goal = "create perm.txt with content PERMISSION_OK one line then final"
    n = {"n": 0}
    def fake_chat(config, model, *args, **kwargs):
        n["n"] += 1
        if n["n"] == 1:
            return json.dumps({"action": "write_file", "args": {"path": "perm.txt", "content": "PERMISSION_OK\n"}})
        if n["n"] == 2:
            return json.dumps({"action": "read_file", "args": {"path": "perm.txt"}})
        return json.dumps({"action": "final", "args": {"answer": "verified"}})
    with tempfile.TemporaryDirectory() as td, mocked_agent_runtime(oa, ["one-model:latest"], fake_chat):
        ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                max_steps=8, yes=False, allow_shell=False, allow_write=False)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            oa.cmd_agent(ns)
        assert_true((Path(td) / "perm.txt").read_text(encoding="utf-8").strip() == "PERMISSION_OK", "agent did not force write permission on all model paths")


def test_repeated_action_loop_switches_and_recovers(oa):
    goal = "create loop_recovered.txt with content LOOP_RECOVERED_OK one line then final"
    calls, good_n = [], {"n": 0}
    def fake_chat(config, model, *args, **kwargs):
        calls.append(model)
        if model == "looper:latest":
            return json.dumps({"action": "list_dir", "args": {"path": "."}})
        good_n["n"] += 1
        if good_n["n"] == 1:
            return json.dumps({"action": "write_file", "args": {"path": "loop_recovered.txt", "content": "LOOP_RECOVERED_OK\n"}})
        if good_n["n"] == 2:
            return json.dumps({"action": "read_file", "args": {"path": "loop_recovered.txt"}})
        return json.dumps({"action": "final", "args": {"answer": "verified"}})
    with tempfile.TemporaryDirectory() as td, mocked_agent_runtime(oa, ["looper:latest", "good-tools:latest"], fake_chat):
        ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                max_steps=8, yes=True, allow_shell=True, allow_write=True)
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            oa.cmd_agent(ns)
        assert_true((Path(td) / "loop_recovered.txt").read_text(encoding="utf-8").strip() == "LOOP_RECOVERED_OK", "repeated action loop did not recover")
        guard_log = err.getvalue()
        assert_true(("repeated identical action blocked" in guard_log or "repeated identical model output blocked" in guard_log), f"loop guard did not trigger: calls={calls} err={guard_log}")


def test_repeated_raw_output_loop_switches_and_recovers(oa):
    goal = "create raw_loop.txt with content RAW_LOOP_OK one line then final"
    calls, good_n = [], {"n": 0}
    bad = "not json repeated forever"
    def fake_chat(config, model, *args, **kwargs):
        calls.append(model)
        if model == "raw-loop:latest":
            return bad
        good_n["n"] += 1
        if good_n["n"] == 1:
            return json.dumps({"action": "write_file", "args": {"path": "raw_loop.txt", "content": "RAW_LOOP_OK\n"}})
        if good_n["n"] == 2:
            return json.dumps({"action": "read_file", "args": {"path": "raw_loop.txt"}})
        return json.dumps({"action": "final", "args": {"answer": "verified"}})
    with tempfile.TemporaryDirectory() as td, mocked_agent_runtime(oa, ["raw-loop:latest", "good-tools:latest"], fake_chat):
        ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                max_steps=10, yes=True, allow_shell=True, allow_write=True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            oa.cmd_agent(ns)
        assert_true((Path(td) / "raw_loop.txt").read_text(encoding="utf-8").strip() == "RAW_LOOP_OK", "repeated raw output loop did not recover")
        assert_true("good-tools:latest" in calls, f"raw output loop did not switch model: {calls}")


def test_final_variants_do_not_end_without_action(oa):
    goal = "create out.txt with content FINAL_VARIANT_OK one line then final"
    calls, bad_n, good_n = [], {"n": 0}, {"n": 0}
    def fake_chat(config, model, *args, **kwargs):
        calls.append(model)
        if model == "bad-final:latest":
            bad_n["n"] += 1
            if bad_n["n"] == 1:
                return json.dumps({"answer": "cannot proceed because no execution result is available"})
            return json.dumps({"answer": "OK."})
        good_n["n"] += 1
        if good_n["n"] == 1:
            return json.dumps({"action": "write_file", "args": {"path": "out.txt", "content": "FINAL_VARIANT_OK\n"}})
        if good_n["n"] == 2:
            return json.dumps({"action": "read_file", "args": {"path": "out.txt"}})
        return json.dumps({"action": "final", "args": {"answer": "verified"}})
    with tempfile.TemporaryDirectory() as td, mocked_agent_runtime(oa, ["bad-final:latest", "good-tools:latest"], fake_chat):
        ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                max_steps=8, yes=True, allow_shell=True, allow_write=True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            oa.cmd_agent(ns)
        assert_true((Path(td) / "out.txt").read_text(encoding="utf-8").strip() == "FINAL_VARIANT_OK", "actionless finals ended or failed to recover")
        assert_true(calls[:2] == ["bad-final:latest", "bad-final:latest"] and "good-tools:latest" in calls, f"bad final variants did not force model switch: {calls}")


def test_post_write_final_requires_readback(oa):
    goal = "create proof.txt with content VERIFY_REQUIRED one line then final"
    n = {"n": 0}
    err = io.StringIO()
    def fake_chat(config, model, *args, **kwargs):
        n["n"] += 1
        if n["n"] == 1:
            return json.dumps({"action": "write_file", "args": {"path": "proof.txt", "content": "VERIFY_REQUIRED\n"}})
        if n["n"] == 2:
            return json.dumps({"action": "final", "args": {"answer": "done"}})
        if n["n"] == 3:
            return json.dumps({"action": "read_file", "args": {"path": "proof.txt"}})
        return json.dumps({"action": "final", "args": {"answer": "verified"}})
    with tempfile.TemporaryDirectory() as td, mocked_agent_runtime(oa, ["one-model:latest"], fake_chat):
        ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                max_steps=8, yes=True, allow_shell=True, allow_write=True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            oa.cmd_agent(ns)
        assert_true((Path(td) / "proof.txt").read_text(encoding="utf-8").strip() == "VERIFY_REQUIRED", "write/readback proof missing")
        assert_true("file verification missing after write/edit" in err.getvalue(), "final after write was not blocked for readback")


def test_readback_mismatch_repairs_deterministically(oa):
    goal = "replace OLD with NEW in sample.txt then final"
    n = {"n": 0}
    def fake_chat(config, model, *args, **kwargs):
        n["n"] += 1
        if n["n"] == 1:
            return json.dumps({"action": "read_file", "args": {"path": "sample.txt"}})
        return json.dumps({"action": "final", "args": {"answer": "done"}})
    with tempfile.TemporaryDirectory() as td, mocked_agent_runtime(oa, ["one-model:latest"], fake_chat):
        sample = Path(td) / "sample.txt"
        sample.write_text("VALUE=OLD\n", encoding="utf-8")
        ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                max_steps=8, yes=True, allow_shell=True, allow_write=True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            oa.cmd_agent(ns)
        text = sample.read_text(encoding="utf-8")
        assert_true("NEW" in text and "OLD" not in text, f"readback mismatch was not repaired: {text}")


def test_readback_path_mismatch_repairs_deterministically(oa):
    goal = "create note.txt containing SILVER-OWL only then final"
    n = {"n": 0}
    def fake_chat(config, model, *args, **kwargs):
        n["n"] += 1
        if n["n"] == 1:
            return json.dumps({"action": "write_file", "args": {"path": ".config/note.txt", "content": "SILVER-OWL\n"}})
        if n["n"] == 2:
            return json.dumps({"action": "read_file", "args": {"path": ".config/note.txt"}})
        return json.dumps({"action": "final", "args": {"answer": "verified"}})
    with tempfile.TemporaryDirectory() as td, mocked_agent_runtime(oa, ["one-model:latest"], fake_chat):
        ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                max_steps=8, yes=True, allow_shell=True, allow_write=True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            oa.cmd_agent(ns)
        expected = Path(td) / "note.txt"
        wrong = Path(td) / ".config" / "note.txt"
        assert_true(expected.exists(), "path mismatch was not repaired into requested file")
        assert_true("SILVER-OWL" in expected.read_text(encoding="utf-8"), "repaired file content mismatch")
        assert_true(wrong.exists(), "original wrong-path artifact should still reflect model mistake for debugging")


def test_invalid_actions_do_not_end_or_stall(oa):
    goal = "create invalid_recovery.txt with content INVALID_RECOVERY_OK one line then final"
    bad_n, good_n, calls = {"n": 0}, {"n": 0}, []
    def fake_chat(config, model, *args, **kwargs):
        calls.append(model)
        if model == "bad-actions:latest":
            bad_n["n"] += 1
            return json.dumps({"action": "list", "args": {"path": "."}})
        good_n["n"] += 1
        if good_n["n"] == 1:
            return json.dumps({"action": "write_file", "args": {"path": "invalid_recovery.txt", "content": "INVALID_RECOVERY_OK\n"}})
        if good_n["n"] == 2:
            return json.dumps({"action": "read_file", "args": {"path": "invalid_recovery.txt"}})
        return json.dumps({"action": "final", "args": {"answer": "verified"}})
    with tempfile.TemporaryDirectory() as td, mocked_agent_runtime(oa, ["bad-actions:latest", "good-tools:latest"], fake_chat):
        ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                max_steps=8, yes=True, allow_shell=True, allow_write=True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            oa.cmd_agent(ns)
        assert_true((Path(td) / "invalid_recovery.txt").read_text(encoding="utf-8").strip() == "INVALID_RECOVERY_OK", "invalid actions prevented recovery")
        assert_true(calls.count("bad-actions:latest") >= 2 and "good-tools:latest" in calls, f"invalid actions did not switch to working model: {calls}")


def test_failed_shell_final_is_blocked_and_recovers(oa):
    goal = "run a command to create run_ok.txt containing SHELL_OK then final"
    bad_n, good_n, calls = {"n": 0}, {"n": 0}, []
    def fake_chat(config, model, *args, **kwargs):
        calls.append(model)
        if model == "bad-shell:latest":
            bad_n["n"] += 1
            if bad_n["n"] == 1:
                return json.dumps({"action": "shell", "args": {"command": "NoSuchCommand_For_Guard_Test"}})
            return json.dumps({"action": "final", "args": {"answer": "done"}})
        good_n["n"] += 1
        if good_n["n"] == 1:
            return json.dumps({"action": "shell", "args": {"command": "Set-Content -LiteralPath run_ok.txt -Value SHELL_OK"}})
        return json.dumps({"action": "final", "args": {"answer": "created"}})
    with tempfile.TemporaryDirectory() as td, mocked_agent_runtime(oa, ["bad-shell:latest", "good-tools:latest"], fake_chat):
        ns = argparse.Namespace(goal=goal, workspace=td, level="auto", task="auto", allow_27b=False,
                                dry_run=False, temperature=0.15, num_ctx=None, num_predict=None,
                                max_steps=8, yes=True, allow_shell=True, allow_write=True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            oa.cmd_agent(ns)
        assert_true((Path(td) / "run_ok.txt").read_text(encoding="utf-8").strip() == "SHELL_OK", "failed shell final did not recover")
        assert_true(("good-tools:latest" in calls) or (Path(td) / "run_ok.txt").exists(), f"failed shell final did not recover: {calls}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repair", action="store_true", help="repair safe stale local model runner state")
    args = ap.parse_args()
    started = time.time()
    results = []
    repair = repair_stale_llama_servers() if args.repair else {"skipped": "no --repair"}
    oa = None
    tests = []
    try:
        oa = load_agent()
        tests = [
            ("compile", lambda: test_compile()),
            ("timeout-classifier", lambda: test_timeout_classifier(oa)),
            ("action-normalization", lambda: test_action_normalization(oa)),
            ("goal-persistence-suffix", lambda: test_goal_persistence_suffix(oa)),
            ("missing-action-guard", lambda: test_missing_action_guard(oa)),
            ("session-auto-agent-file-edit-guard", lambda: test_session_auto_agent_file_edit_guard(oa)),
            ("model-order", lambda: test_model_order(oa)),
            ("deterministic-fallback-write", lambda: test_deterministic_fallback_write(oa)),
            ("timeout-cmd-agent-fallback", lambda: test_timeout_cmd_agent_fallback(oa)),
            ("workspace-path-guard", lambda: test_workspace_path_maps_container_and_blocks_escape(oa)),
            ("blocked-final-switches-model", lambda: test_blocked_final_switches_model(oa)),
            ("code-edit-line-regex-patch-tools", lambda: test_code_edit_line_regex_patch_tools(oa)),
            ("replace-in-file-tool", lambda: test_replace_in_file_tool(oa)),
            ("binary-info-and-replace-tools", lambda: test_binary_info_and_replace_tools(oa)),
            ("reverse-binary-analysis-tools", lambda: test_reverse_binary_analysis_tools(oa)),
            ("binary-refusal-real-patch-fallback", lambda: test_binary_refusal_routes_to_real_patch_fallback(oa)),
            ("web-search-fallback-and-refusals", lambda: test_web_search_fallback_and_refusal_patterns(oa)),
            ("re-tool-inventory-permission-guard", lambda: test_resolve_tool_skips_permission_denied_dirs(oa)),
            ("preflight-does-not-intercept-broad-agent-jobs", lambda: test_preflight_does_not_intercept_broad_agent_jobs(oa)),
            ("forced-permissions-when-args-false", lambda: test_forced_permissions_even_when_args_false(oa)),
            ("repeated-action-loop-recovers", lambda: test_repeated_action_loop_switches_and_recovers(oa)),
            ("repeated-raw-output-loop-recovers", lambda: test_repeated_raw_output_loop_switches_and_recovers(oa)),
            ("final-variants-no-action", lambda: test_final_variants_do_not_end_without_action(oa)),
            ("post-write-final-requires-readback", lambda: test_post_write_final_requires_readback(oa)),
            ("readback-mismatch-deterministic-repair", lambda: test_readback_mismatch_repairs_deterministically(oa)),
            ("readback-path-mismatch-deterministic-repair", lambda: test_readback_path_mismatch_repairs_deterministically(oa)),
            ("invalid-actions-recover", lambda: test_invalid_actions_do_not_end_or_stall(oa)),
            ("failed-shell-final-recovers", lambda: test_failed_shell_final_is_blocked_and_recovers(oa)),
        ]
        for name, fn in tests:
            t0 = time.time()
            try:
                fn()
                results.append({"name": name, "ok": True, "seconds": round(time.time() - t0, 3)})
            except Exception as e:
                results.append({"name": name, "ok": False, "seconds": round(time.time() - t0, 3), "error": repr(e)})
    finally:
        report = {
            "ok": all(r.get("ok") for r in results) and bool(results),
            "seconds": round(time.time() - started, 3),
            "repair": repair,
            "results": results,
            "agent": str(AGENT),
        }
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
    if not all(r.get("ok") for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
