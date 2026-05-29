# -*- coding: utf-8 -*-
"""Subprocess regression tests for binary/reversing entrypoints.

This verifies the actual AI.exe launcher, not only imported Python functions.
Every binary/reversing entrypoint must run real binary tools and must not emit
the old "Provide or place the target..." completion.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "AI.exe"
TARGET = ROOT / "AI.exe"
FORBIDDEN = (
    "Provide or place the target",
    "available files/tools were inspected",
    "target EXE/DLL/SYS/BIN in the workspace to patch exact bytes",
)


def run_case(name, args, timeout=60):
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run(
        [str(EXE), *args],
        cwd=str(ROOT),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=env,
    )
    combined = (p.stdout or "") + "\n" + (p.stderr or "")
    has_real_binary_action = (
        "[tool:binary_info]" in combined
        or "[tool:binary_patch_offset]" in combined
        or '"action": "binary_patch_offset"' in combined
        or "binary target found by search_files and inspected" in combined
        or "binary inspected with binary_info" in combined
    )
    forbidden_hits = [s for s in FORBIDDEN if s in combined]
    tool_lines = [line for line in combined.splitlines() if line.startswith("[tool:")]
    broken_or_noisy_tool_lines = [
        line for line in tool_lines
        if len(line) > 1300
        or '"strings":' in line
        or (line.rstrip().endswith('"encoding"') or line.rstrip().endswith('"text"'))
    ]
    ok = p.returncode == 0 and has_real_binary_action and not forbidden_hits and not broken_or_noisy_tool_lines
    print(f"{'PASS' if ok else 'FAIL'} {name} exit={p.returncode} has_real_binary_action={has_real_binary_action} forbidden={forbidden_hits} bad_tool_lines={len(broken_or_noisy_tool_lines)}")
    if not ok:
        if broken_or_noisy_tool_lines:
            print("--- bad tool lines ---")
            print("\n".join(broken_or_noisy_tool_lines[:5]))
        print("--- stdout ---")
        print((p.stdout or "")[:4000])
        print("--- stderr ---")
        print((p.stderr or "")[:6000])
        raise AssertionError(name)


def run_web_context_case(name, args, timeout=60):
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run(
        [str(EXE), *args],
        cwd=str(ROOT),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=env,
    )
    combined = (p.stdout or "") + "\n" + (p.stderr or "")
    has_web_action = "[tool:fetch_url]" in combined or "[tool:web_search]" in combined or "fetched URL" in combined
    has_binary_action = "[tool:binary_info]" in combined or "[tool:search_files]" in combined or "binary target found" in combined
    ok = p.returncode == 0 and has_web_action and not has_binary_action
    print(f"{'PASS' if ok else 'FAIL'} {name} exit={p.returncode} has_web_action={has_web_action} has_binary_action={has_binary_action}")
    if not ok:
        print("--- stdout ---")
        print((p.stdout or "")[:4000])
        print("--- stderr ---")
        print((p.stderr or "")[:6000])
        raise AssertionError(name)


def main() -> int:
    target = str(TARGET)
    old_failure = (
        f"no-howto final blocked until real action: no tool action executed [tool:search_files] {target} "
        "Done: binary/reversing tool path checked. Provide or place the target EXE/DLL/SYS/BIN "
        "in the workspace to patch exact bytes; available files/tools were inspected."
    )
    search_followup = "binary/reversing tool path checked; inspect available exe target and do real action"
    external_root = Path(tempfile.gettempdir()) / "Program Files (x86)" / "MarkAny" / "WebDRMNoAX"
    external_root.mkdir(parents=True, exist_ok=True)
    external_target = external_root / "MaWebDRMSvc_entrypoint.exe"
    shutil.copy2(TARGET, external_target)
    external_patch_goal = f"patch binary {external_target} offset 0x1f4 new_hex 90 90 90 90 90 90 90 90"

    cases = [
        ("agent absolute old failure", ["agent", old_failure, "--workspace", str(ROOT)]),
        ("auto explicit absolute old failure", ["auto", "--workspace", str(ROOT), old_failure]),
        ("default auto absolute", ["--workspace", str(ROOT), f"inspect binary {target}"]),
        ("agent external Program Files-like patch", ["agent", external_patch_goal, "--workspace", str(ROOT)]),
        ("agent search followup", ["agent", search_followup, "--workspace", str(ROOT)]),
        ("default auto search followup", ["--workspace", str(ROOT), search_followup]),
        ("session once search followup", ["session", search_followup, "--workspace", str(ROOT), "--once"]),
    ]
    for name, args in cases:
        run_case(name, args)
    assert external_target.read_bytes()[0x1f4:0x1fc] == bytes([0x90]) * 8, "external entrypoint patch did not modify requested file"
    contaminated_web = f"이전 대화 컨텍스트:\nuser: old binary log {target}\n\n현재 작업:\ncheck https://example.com and verify the page"
    run_web_context_case("session web ignores old binary context", ["session", contaminated_web, "--workspace", str(ROOT), "--once"])
    print("PASS regression_binary_entrypoints_test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
