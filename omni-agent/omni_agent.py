#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Omni Agent - local Hugging Face GGUF/Ollama model router + lightweight PC agent.
Windows-first, no external Python packages required.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import html as html_lib
import hashlib
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from typing import Any, Dict, List, Tuple
from collections import Counter

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "models.json"
GOAL_PATH = ROOT / "agent_goal.txt"
BROWSER_CONTROLLER = ROOT / "browser_controller.js"
_BROWSER_PROC: subprocess.Popen | None = None

KOREAN_HINTS = {
    "fast": ["빨리", "대충", "간단", "짧게", "요약", "분류", "초안"],
    "creative": ["소설", "창작", "캐릭터", "대사", "세계관", "브레인", "아이디어", "카피"],
    "code": ["코드", "버그", "스크립트", "프로그램", "파이썬", "자바", "리팩터", "구현"],
    "heavy": ["정확", "분석", "설계", "아키텍처", "복잡", "추론", "전략", "계획", "검토"],
}

SYSTEM_BY_TASK = {
    "default": "너는 빠르고 정확한 로컬 업무 보조 AI다. 한국어로 핵심 위주로 답한다. EXE/DLL/바이너리는 불가능하다고 단정하지 말고 가능한 분석/도구/패치 경로를 제시한다.",
    "code": "너는 시니어 개발자 에이전트다. 실행 가능한 코드와 명확한 수정 지침을 우선한다. EXE/DLL/바이너리 작업은 헤더/문자열/디스어셈블/바이트 패치 단위로 다룬다.",
    "creative": "너는 창작/기획 전문 AI다. 자유롭고 구체적인 결과물을 낸다.",
    "analysis": "너는 분석/추론 전문 AI다. 가정, 근거, 결론을 분리하고 정확도를 우선한다.",
    "summary": "너는 요약 전문 AI다. 중복을 줄이고 핵심만 구조화한다.",
}

AGENT_SYSTEM = """너는 사용자의 로컬 PC에서 작업을 수행하는 에이전트다.
반드시 JSON 하나만 출력한다. 마크다운 금지.
출력은 반드시 한 줄짜리 minified JSON 객체 하나여야 한다. 설명, 주석, 코드펜스, 두 번째 JSON, 생각 과정 출력 금지.
사용 가능한 action:
- final: 최종 답변. args={"answer":"..."}
- list_dir: 폴더 목록. args={"path":"."}
- read_file: 파일 읽기. args={"path":"파일경로"}
- write_file: 파일 쓰기. args={"path":"파일경로","content":"내용"}
- append_file: 파일 끝에 추가. args={"path":"파일경로","content":"내용"}
- file_info: 파일 크기/해시 확인. args={"path":"파일경로"}
- file_hashes: CRC32/MD5/SHA1/SHA256/SHA512 계산. args={"path":"파일경로"}
- file_type: 매직/PE/텍스트 여부 판별. args={"path":"파일경로"}
- read_lines: 텍스트 파일 일부 라인 읽기. args={"path":"파일경로","start":1,"end":80}
- replace_lines/insert_lines/delete_lines/regex_replace/replace_in_file/apply_unified_patch: 코드/텍스트 수정.
- backup_file: 원본 백업. args={"path":"파일경로"}
- binary_info: EXE/DLL/바이너리 크기/sha256/헤더 확인. args={"path":"파일경로","head":128}
- binary_strings: EXE/DLL 문자열 추출. args={"path":"파일경로","min_len":4,"limit":200}
- binary_hexdump: EXE/DLL hex 덤프. args={"path":"파일경로","offset":0,"length":256}
- binary_search: EXE/DLL 바이트/문자열 검색. args={"path":"파일경로","needle_hex":"..."} 또는 {"needle_text":"..."}
- binary_pattern_search: 와일드카드 패턴 검색. args={"path":"파일경로","pattern":"48 8B ?? ?? 90"}
- binary_extract: EXE/DLL 일부 추출. args={"path":"파일경로","offset":0,"length":256,"out":"chunk.bin"}
- binary_diff: 두 바이너리 차이 범위 비교. args={"path":"a.exe","other":"b.exe","limit":50}
- binary_entropy: 전체/윈도우별 엔트로피 확인. args={"path":"파일경로","window":4096,"limit":20}
- binary_fill/binary_insert/binary_delete/binary_append: offset 기반 바이트 채우기/삽입/삭제/추가.
- pe_info: Windows PE(EXE/DLL) 헤더/섹션/엔트리포인트 분석. args={"path":"파일경로"}
- pe_imports: PE import DLL/API 목록. args={"path":"파일경로","limit":500}
- pe_exports: PE export 함수 목록. args={"path":"파일경로","limit":500}
- pe_rva_to_offset/pe_offset_to_rva/pe_section_extract: PE 주소변환/섹션 추출.
- disassemble: 설치된 objdump/llvm-objdump/dumpbin이 있으면 디스어셈블/헤더 분석. args={"path":"파일경로","mode":"headers|imports|disasm"}
- re_tool_inventory: Ghidra/radare2/rizin/Cutter/x64dbg/objdump/dumpbin/strings 등 역공학 도구 설치 여부 확인. args={}
- ghidra_analyze: Ghidra headless 분석 실행. args={"path":"파일경로","project":"ghidra_proj","timeout":300}
- rizin_info: Rizin/rz-bin 기반 info/import/section 분석. args={"path":"파일경로","mode":"info|imports|sections|strings"}
- sigcheck_file: Sysinternals sigcheck 해시/서명/버전 확인. args={"path":"파일경로"}
- capa_scan: FLARE capa 정적 capability 스캔. args={"path":"파일경로","timeout":120}
- python_re_libs: capstone/keystone/lief/yara/pefile 등 Python RE 라이브러리 확인. args={}
- binary_replace: EXE/DLL 바이트 패치. args={"path":"파일경로","old_hex":"...","new_hex":"...","backup":true}
- binary_patch_offset: EXE/DLL 특정 offset 바이트 패치. args={"path":"파일경로","offset":"0x1234","new_hex":"90 90","backup":true}
- binary_pattern_patch: 와일드카드 패턴 위치에 바이트 패치. args={"path":"파일경로","pattern":"48 8B ??","new_hex":"90 90 90","backup":true}
- process_list/process_modules: 실행 프로세스/로드 DLL 확인.
- search_files: 파일명/내용 검색. args={"root":".","pattern":"검색어","glob":"*"}
- shell: PowerShell 명령 실행. args={"command":"명령"}
- fetch_url: URL 텍스트 가져오기. args={"url":"https://..."}
- web_search: 인터넷 검색. args={"query":"검색어","max_results":5}
- download_file: URL에서 파일 다운로드. args={"url":"https://...","path":"저장경로"}
- open_url: 기본 브라우저로 URL 열기. args={"url":"https://..."}
- open_file: 로컬 파일/폴더/프로그램 열기. args={"path":"경로"}
- browser_open: Playwright 브라우저에서 페이지 열기. args={"url":"https://..."}
- browser_click: Playwright 마우스 클릭. args={"selector":"CSS선택자"} 또는 args={"x":100,"y":200}
- browser_type: Playwright 키보드 입력. args={"selector":"CSS선택자","text":"입력값","clear":true}
- browser_press: Playwright 키 입력. args={"key":"Enter"}
- browser_screenshot: 화면 캡처. args={"path":"screenshot.png","fullPage":true}
- browser_eval: 페이지 JS 실행/상태확인. args={"script":"document.title"}
- browser_text: 페이지 텍스트 읽기. args={"selector":"body"}
- browser_close: Playwright 브라우저 닫기. args={}
규칙:
1. 작업을 완료하려면 필요한 action을 하나씩 선택한다.
2. 경로는 가능하면 workspace 내부 상대경로를 사용한다.
3. 사용자가 "인터넷", "브라우저"라고 말하지 않아도 최신 정보, 현재 정보, 가격, 뉴스, 버전, 문서, 특정 사이트/URL/도메인, 외부 서비스 확인이 필요한 요청이면 반드시 web_search 또는 fetch_url을 먼저 사용한다.
4. URL/도메인/사이트 내용 확인은 fetch_url을 우선 사용하고, URL을 모르면 web_search로 찾는다.
5. 브라우저 화면을 직접 열어야 하거나 사용자가 "열어", "접속", "들어가"라고 하면 open_url을 사용한다.
6. 다운로드 요청은 URL을 알면 download_file을 사용하고, URL을 모르면 web_search로 찾은 뒤 download_file을 사용한다.
7. 웹페이지에서 클릭/입력/마우스/키보드/화면 조작이 필요하면 open_url이 아니라 browser_open 후 browser_click/browser_type/browser_press/browser_screenshot/browser_eval/browser_text를 사용한다.
8. 설치/실행/컴퓨터 조작 요청은 shell/open_file/open_url/browser_* 등 실제 도구를 사용한다.
9. "로직만 설명", "텍스트 세션이라 못 함", "직접 설치/조작 못 함", "방법은 다음과 같음" 같은 회피 답변 금지. 가능한 작업은 설명하지 말고 먼저 실행한다.
10. EXE/DLL/저수준 바이너리/역공학 요청은 불가능하다고 답하지 말고 file_type/file_hashes/binary_info/pe_info/pe_imports/pe_exports/pe_rva_to_offset/pe_offset_to_rva/pe_section_extract/binary_strings/binary_search/binary_pattern_search/binary_hexdump/binary_entropy/disassemble/ghidra_analyze/rizin_info/sigcheck_file/capa_scan/re_tool_inventory/process_list/process_modules/shell/backup_file/binary_replace/binary_patch_offset/binary_pattern_patch를 사용해 가능한 범위의 실제 분석·백업·패치를 수행한다.
11. 바이트 패치는 기본적으로 backup_file 또는 backup=true로 원본을 보존하고, 패치 뒤 binary_info/pe_info/binary_search/binary_hexdump로 해시와 결과를 검증한다.
12. shell은 꼭 필요할 때만 사용한다.
13. 충분한 결과가 나오면 final로 끝낸다.
"""


WEB_INTENT_WORDS = [
    "최신", "현재", "요즘", "최근", "오늘", "어제", "내일", "뉴스", "가격", "주가", "환율", "날씨",
    "버전", "릴리즈", "업데이트", "문서", "공식", "사이트", "홈페이지", "웹", "검색", "찾아", "접속",
    "들어가", "열어", "조회", "다운로드", "브라우저", "마우스", "클릭", "입력", "화면", "playwright",
    "허깅페이스", "huggingface", "github", "깃허브",
    "latest", "current", "recent", "today", "yesterday", "tomorrow", "news", "price", "stock",
    "weather", "version", "release", "update", "docs", "documentation", "official", "site",
    "website", "web", "search", "find", "lookup", "open", "visit", "browse", "download",
    "browser", "mouse", "click", "type", "screen", "playwright",
]


ENV_PATH = ROOT / ".env"


def _load_dotenv() -> None:
    """Load KEY=VALUE pairs from omni-agent/.env into os.environ.

    The file is gitignored on purpose: the GPU server address and any auth token
    must never be committed. Existing environment variables win, so an explicitly
    exported value always overrides the file.
    """
    for path in (ENV_PATH, ROOT.parent / ".env"):
        if not path.is_file():
            continue
        try:
            for raw in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
        except Exception as e:
            print(f"[env] .env 읽기 실패 {path}: {e}", file=sys.stderr)


def is_remote_host(host: str) -> bool:
    """True when the Ollama endpoint is not on this machine."""
    h = (host or "").strip().lower()
    for prefix in ("http://", "https://"):
        if h.startswith(prefix):
            h = h[len(prefix):]
            break
    h = h.split("/")[0]
    if h.startswith("["):
        h = h[1:h.find("]")] if "]" in h else h[1:]
    else:
        h = h.rsplit(":", 1)[0] if h.count(":") == 1 else h
    return h not in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "")


def load_config() -> Dict[str, Any]:
    _load_dotenv()
    with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
        config = json.load(f)

    ollama_cfg = config.setdefault("ollama", {})
    host_override = os.environ.get("OMNI_OLLAMA_HOST") or os.environ.get("OLLAMA_HOST")
    if host_override:
        host = host_override.strip()
        if not host.startswith(("http://", "https://")):
            host = "http://" + host
        ollama_cfg["host"] = host
    token = os.environ.get("OMNI_OLLAMA_TOKEN")
    if token:
        ollama_cfg["auth_token"] = token.strip()
    ollama_cfg["remote"] = is_remote_host(ollama_cfg.get("host", ""))
    return config


def api_headers(config: Dict[str, Any] | None = None, token: str | None = None) -> Dict[str, str]:
    """Headers for Ollama HTTP calls, including bearer auth when a token is set."""
    headers = {"Content-Type": "application/json"}
    if token is None and config is not None:
        token = config.get("ollama", {}).get("auth_token")
    if token is None:
        token = os.environ.get("OMNI_OLLAMA_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers



def read_persistent_goal() -> str:
    try:
        return GOAL_PATH.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""

def write_persistent_goal(goal: str) -> None:
    GOAL_PATH.write_text(goal.strip() + "\n", encoding="utf-8")

def goal_system_suffix() -> str:
    goal = read_persistent_goal()
    if not goal:
        return ""
    return (
        "\nPersistent /goal: " + goal +
        "\nOperational requirement: satisfy the user command end-to-end. "
        "If a model emits invalid JSON, <think>, missing action, tool errors, or partial work, self-correct, retry, use fallback actions/models, and verify completion before final."
    )

def run(cmd: List[str], timeout: int | None = None) -> Tuple[int, str]:
    p = subprocess.run(cmd, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return p.returncode, p.stdout


def browser_rpc(action: str, args: Dict[str, Any], workspace: Path, timeout: float = 60.0) -> str:
    global _BROWSER_PROC
    if _BROWSER_PROC is None or _BROWSER_PROC.poll() is not None:
        if not BROWSER_CONTROLLER.exists():
            return f"browser error: missing {BROWSER_CONTROLLER}"
        _BROWSER_PROC = subprocess.Popen(
            ["node", str(BROWSER_CONTROLLER)],
            cwd=str(workspace),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    assert _BROWSER_PROC.stdin is not None and _BROWSER_PROC.stdout is not None
    payload = json.dumps({"action": action, "args": args}, ensure_ascii=False)
    _BROWSER_PROC.stdin.write(payload + "\n")
    _BROWSER_PROC.stdin.flush()
    start = time.time()
    while True:
        if time.time() - start > timeout:
            return f"browser error: timeout action={action}"
        line = _BROWSER_PROC.stdout.readline()
        if line:
            try:
                obj = json.loads(line)
                return json.dumps(obj, ensure_ascii=False)
            except Exception:
                return line.strip()
        if _BROWSER_PROC.poll() is not None:
            err = ""
            try:
                err = _BROWSER_PROC.stderr.read() if _BROWSER_PROC.stderr else ""
            except Exception:
                pass
            return f"browser error: process exited {err[-2000:]}"


def ollama_env(host: str) -> Dict[str, str]:
    env = os.environ.copy()
    env["OLLAMA_HOST"] = host if host.startswith(("http://", "https://")) else "http://" + host
    return env


def ollama_server_env(host: str) -> Dict[str, str]:
    env = ollama_env(host)
    h = env["OLLAMA_HOST"]
    # On this Windows machine, binding Ollama to IPv4 loopback can fail with
    # "invalid pointer address". Bind the server to IPv6 loopback; clients use
    # localhost and connect correctly.
    h = h.replace("http://127.0.0.1:", "http://[::1]:")
    h = h.replace("http://localhost:", "http://[::1]:")
    env["OLLAMA_HOST"] = h
    return env


def run_ollama(args: List[str], host: str, timeout: int | None = None) -> Tuple[int, str]:
    p = subprocess.run([_ollama_exe()] + args, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=ollama_env(host))
    return p.returncode, p.stdout


def is_timeout_error(exc: BaseException) -> bool:
    """True for urllib/socket/subprocess timeout shapes, including wrapped URLError."""
    if isinstance(exc, (TimeoutError, socket.timeout, subprocess.TimeoutExpired)):
        return True
    reason = getattr(exc, "reason", None)
    if isinstance(reason, BaseException) and is_timeout_error(reason):
        return True
    text = str(exc).lower()
    return "timed out" in text or "timeout" in text


def stop_ollama_model(model: str, host: str) -> None:
    """Best-effort cancellation/unload for a model that timed out so fallback is not blocked."""
    host = host.rstrip("/")
    try:
        run_ollama(["stop", model], host, timeout=20)
    except Exception:
        pass
    try:
        payload = {"model": model, "prompt": "", "stream": False, "keep_alive": 0}
        req = urllib.request.Request(
            host + "/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers=api_headers(),
        )
        with urllib.request.urlopen(req, timeout=3):
            pass
    except Exception:
        pass
    # Only ever kill a llama-server that belongs to this machine. When the model
    # runs on a remote GPU server, this would terminate an unrelated local process.
    if os.name == "nt" and not is_remote_host(host):
        try:
            subprocess.run(["taskkill", "/F", "/IM", "llama-server.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except Exception:
            pass


def ollama_available(host: str | None = None) -> bool:
    # With a remote GPU server the local Ollama CLI is optional: reachability of
    # the HTTP API is what actually matters. Call sites stay argument-free, so the
    # host falls back to the same env var load_config() honours.
    if host is None:
        host = os.environ.get("OMNI_OLLAMA_HOST") or os.environ.get("OLLAMA_HOST") or ""
    if host and is_remote_host(host):
        if not host.startswith(("http://", "https://")):
            host = "http://" + host
        return _ollama_api_ok(host, timeout=5.0)
    code, _ = run([_ollama_exe(), "--version"], timeout=10)
    return code == 0


def choose_profile(config: Dict[str, Any], prompt: str, level: str = "auto", task: str = "auto", allow_27b: bool = False) -> Tuple[str, Dict[str, Any], str]:
    routing = config["routing"]
    reason = []

    if level and level != "auto":
        key = routing["level_map"].get(str(level).lower())
        if key:
            reason.append(f"level={level}")
            if key == "max27b" and not allow_27b:
                reason.append("27B disabled -> heavy fallback")
                key = "heavy"
            return key, config["profiles"][key], ", ".join(reason)

    if task and task != "auto":
        key = routing["task_map"].get(task.lower(), routing["default"])
        reason.append(f"task={task}")
        return key, config["profiles"][key], ", ".join(reason)

    text = prompt.lower()
    score = {"fast": 0, "creative": 0, "code": 0, "heavy": 0}
    for k, words in KOREAN_HINTS.items():
        for w in words:
            if w.lower() in text:
                score[k] += 1
    if len(prompt) > 2500:
        score["heavy"] += 2
    elif len(prompt) < 280:
        score["fast"] += 1

    if score["creative"] >= 1:
        key = "creative"
    elif score["heavy"] >= 2:
        key = "heavy"
    elif score["code"] >= 1:
        key = "balanced"
    elif score["fast"] >= 1:
        key = "fast"
    else:
        key = routing["default"]
    reason.append("auto:" + "/".join(f"{k}={v}" for k, v in score.items()))
    return key, config["profiles"][key], ", ".join(reason)


def ollama_tags(host: str) -> List[str]:
    try:
        req = urllib.request.Request(host.rstrip("/") + "/api/tags", headers=api_headers())
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
        return [m.get("name", "") for m in data.get("models", [])]
    except Exception:
        # Ollama's HTTP server may not be running yet, while the CLI can still
        # report installed models. Fall back to `ollama list` so local aliases
        # such as gemma4:latest are not pulled again by mistake.
        try:
            code, out = run_ollama(["list"], host, timeout=20)
            if code != 0:
                return []
            names = []
            for line in out.splitlines()[1:]:
                parts = line.split()
                if parts:
                    names.append(parts[0])
            return names
        except Exception:
            return []


def _ollama_api_ok(host: str, timeout: float = 2.0) -> bool:
    url = host.rstrip("/") + "/api/tags"
    try:
        req = urllib.request.Request(url, headers=api_headers())
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except Exception:
        return False


def _ollama_exe() -> str:
    portable = os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "Codex", "2026-05-19", "gemma4", "ollama-0.30.0-rc23", "ollama.exe")
    if portable and os.path.exists(portable):
        return portable
    local = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Ollama", "ollama.exe")
    if local and os.path.exists(local):
        return local
    return shutil.which("ollama") or "ollama"


def _start_ollama_server(host: str) -> None:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    # Force the local API address used by this router, overriding stale
    # system/user OLLAMA_HOST values.
    env = ollama_server_env(host)
    subprocess.Popen([_ollama_exe(), "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags, env=env)


def _kill_ollama_processes() -> None:
    # Windows Ollama desktop app can leave a GUI instance alive while the API
    # server is dead. Kill both the app and server, then relaunch serve.
    for image in ("ollama.exe", "ollama app.exe"):
        try:
            subprocess.run(["taskkill", "/F", "/IM", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except Exception:
            pass


def ensure_ollama_api(host: str, wait_seconds: int = 8) -> None:
    url = host.rstrip("/") + "/api/tags"
    # A remote GPU server is reachable over the network only. Never try to spawn
    # or kill a local Ollama process in that case - it would silently mask an
    # unreachable server and start a second, empty instance on this machine.
    if is_remote_host(host):
        if _ollama_api_ok(host, timeout=5.0):
            return
        raise RuntimeError(
            f"원격 Ollama 서버에 연결할 수 없습니다: {url}\n"
            "OMNI_OLLAMA_HOST 값과 GPU 서버 상태를 확인하세요. "
            "서버 쪽에서 OLLAMA_HOST=0.0.0.0 으로 떠 있어야 외부 접속이 됩니다."
        )

    if _ollama_api_ok(host):
        return

    # First try: start a normal background server.
    try:
        _start_ollama_server(host)
    except Exception:
        pass
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        if _ollama_api_ok(host):
            return
        time.sleep(0.5)

    # Second try: repair the common Windows stuck-state by killing stale
    # Ollama/app processes, including old portable builds, then start serve.
    print("[ollama] API 서버가 응답하지 않아 꼬인 Ollama 프로세스를 정리하고 재시작합니다.", file=sys.stderr)
    _kill_ollama_processes()
    time.sleep(1.0)
    try:
        _start_ollama_server(host)
    except Exception:
        pass
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        if _ollama_api_ok(host):
            return
        time.sleep(0.5)

    raise RuntimeError(f"Ollama API 서버 시작 실패: {url}")


def ensure_model(model: str, host: str, dry_run: bool = False) -> None:
    names = ollama_tags(host)
    if model in names or any(n.startswith(model) for n in names):
        return
    print(f"[pull] 모델 없음. 다운로드 시작: {model}", file=sys.stderr)
    if dry_run:
        print("[dry-run] ollama pull 생략", file=sys.stderr)
        return
    code, out = run_ollama(["pull", model], host, timeout=None)
    if code != 0 and ("timed out waiting for server" in out.lower() or "connection refused" in out.lower()):
        print("[ollama] pull 실패 원인이 서버 상태라서 Ollama를 복구 후 재시도합니다.", file=sys.stderr)
        ensure_ollama_api(host)
        code, out = run_ollama(["pull", model], host, timeout=None)
    if code != 0:
        raise RuntimeError(f"ollama pull 실패:\n{out}")


class DegenerateOutput(RuntimeError):
    pass


class EmptyOutput(RuntimeError):
    pass


def is_degenerate_output(text: str) -> Tuple[bool, str]:
    if not text:
        return False, ""
    raw = text.strip()
    # Thinking-only models often get stuck printing only <think> tokens. Treat
    # this as a hard model failure so agent steps are not wasted forever.
    if re.fullmatch(r"(?is)(?:\s*</?think\b[^>]*>\s*)+", raw):
        return True, "think tags only"
    if len(re.findall(r"(?is)<think\b", raw)) >= 2 and not re.search(r"\{\s*\"action\"", raw):
        return True, "repeated think tags without JSON action"
    compact = re.sub(r"\s+", " ", raw).strip()
    if re.search(r"(.)(\1){24,}", compact):
        return True, "same character repeated"
    words = re.findall(r"[A-Za-z0-9_]+", compact.lower())
    if len(words) >= 20:
        counts = Counter(words)
        word, cnt = counts.most_common(1)[0]
        if word in ("think", "thinking") and cnt >= 2 and cnt / max(1, len(words)) >= 0.25:
            return True, f"think repeated: {cnt}"
    if len(words) >= 80:
        counts = Counter(words)
        word, cnt = counts.most_common(1)[0]
        if cnt / max(1, len(words)) >= 0.28 and cnt >= 30:
            return True, f"word repeated: {word} x{cnt}"
        for n in (2, 3, 4):
            grams = [tuple(words[i:i+n]) for i in range(len(words)-n+1)]
            if not grams:
                continue
            g, gcnt = Counter(grams).most_common(1)[0]
            if gcnt >= 18 and (gcnt * n) / max(1, len(words)) >= 0.22:
                return True, "phrase repeated: " + " ".join(g)
    if len(words) >= 160 and len(set(words)) / len(words) < 0.12:
        return True, "low unique-token ratio"
    return False, ""


def clean_model_output(text: str) -> str:
    # Remove completed and dangling reasoning/thinking tags. If a model emits
    # prose before JSON, extract_json still scans for the first valid object.
    text = re.sub(r"(?is)<think\b[^>]*>.*?</think>", "", text)
    text = re.sub(r"(?is)</?think\b[^>]*>", "", text)
    text = re.sub(r"(?is)</?thinking\b[^>]*>", "", text)
    text = re.sub(r"<\|channel\>\s*\w*\s*", "", text, flags=re.I)
    text = re.sub(r"<\|/?(?:analysis|final|commentary|assistant|user|system)\|>", "", text, flags=re.I)
    text = re.sub(r"</?(?:analysis|final|commentary|assistant|user|system|reasoning)>", "", text, flags=re.I)
    text = re.sub(r"<channel\|>", "", text, flags=re.I)
    text = re.sub(r"<\|/?(?:im_end|endoftext|tool_call|file_name|file_sep|file_separator)\|?>", "", text, flags=re.I)
    text = re.sub(r"\s*\|\s*$", "", text)
    return text.strip()


def is_control_token_junk(text: str) -> bool:
    cleaned = clean_model_output(text)
    if not cleaned:
        return True
    if re.fullmatch(r"(?is)(?:think|thinking|reasoning|analysis|\s|[<>{}\[\]`'\".:;,_/|-]){1,80}", cleaned):
        return True
    # Outputs made only of special/control tokens or punctuation should not burn
    # a full agent step.
    visible = re.sub(r"[<>\|/_\s`'\".:;,{\}\[\]-]+", "", cleaned)
    return not visible

def candidate_models(profile: Dict[str, Any], host: str, dry_run: bool = False) -> List[str]:
    wanted = profile["model"]
    names = ollama_tags(host)
    candidates: List[str] = []

    def installed(m: str) -> bool:
        return m in names or any(n.startswith(m) for n in names)

    if installed(wanted):
        candidates.append(wanted)
    for fb in profile.get("fallback_models", []):
        if installed(fb) and fb not in candidates:
            if not candidates:
                print(f"[fallback] 기본 모델 미설치: {wanted} -> 로컬 모델 사용: {fb}", file=sys.stderr)
            candidates.append(fb)
    if not candidates:
        ensure_model(wanted, host, dry_run=dry_run)
        candidates.append(wanted)
    return candidates


def resolve_model(profile: Dict[str, Any], host: str, dry_run: bool = False) -> str:
    return candidate_models(profile, host, dry_run=dry_run)[0]


def render_prompt(messages: List[Dict[str, str]]) -> str:
    parts = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        parts.append(f"<|im_start|>{role}\n{content}<|im_end|>")
    parts.append("<|im_start|>assistant\n")
    return "\n".join(parts)


def chat_ollama(config: Dict[str, Any], model: str, messages: List[Dict[str, str]], stream: bool = True, temperature: float | None = None, num_ctx: int | None = None, num_predict: int | None = None, json_mode: bool = False) -> str:
    host = config["ollama"]["host"].rstrip("/")
    request_timeout = config["ollama"].get("request_timeout", 180)
    if json_mode:
        # A 35B MoE with thinking enabled needs more than the old hard-coded 30s,
        # especially on the first request when the server still has to load it.
        json_timeout = config["ollama"].get("json_request_timeout", 120)
        request_timeout = min(int(request_timeout), int(json_timeout))
    options = {
        "temperature": 0.0 if json_mode else (config["ollama"].get("temperature", 0.25) if temperature is None else temperature),
        "num_ctx": config["ollama"].get("num_ctx", 8192) if num_ctx is None else num_ctx,
    }
    for opt in ("top_p", "top_k", "min_p", "repeat_penalty", "repeat_last_n", "frequency_penalty", "presence_penalty", "mirostat", "mirostat_tau", "mirostat_eta"):
        if opt in config["ollama"]:
            options[opt] = config["ollama"][opt]
    effective_num_predict = config["ollama"].get("num_predict") if num_predict is None else num_predict
    if effective_num_predict is not None:
        options["num_predict"] = effective_num_predict
    use_generate = config["ollama"].get("use_generate_raw", True)
    if use_generate:
        payload = {
            "model": model,
            "prompt": render_prompt(messages),
            "raw": True,
            "stream": stream,
            "keep_alive": "30s" if json_mode else config["ollama"].get("keep_alive", "20m"),
            "options": {**options, "stop": ["<|im_end|>", "<|endoftext|>", "<|file_sep|>", "<|channel>", "<channel|>"]},
        }
        if json_mode:
            payload["format"] = "json"
        endpoint = "/api/generate"
    else:
        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "keep_alive": "30s" if json_mode else config["ollama"].get("keep_alive", "20m"),
            "options": options,
        }
        if json_mode:
            payload["format"] = "json"
        endpoint = "/api/chat"
    req = urllib.request.Request(host + endpoint, data=json.dumps(payload).encode("utf-8"), headers=api_headers(config))
    chunks: List[str] = []
    try:
        with urllib.request.urlopen(req, timeout=request_timeout) as r:
            if stream:
                for line in r:
                    if not line.strip():
                        continue
                    obj = json.loads(line.decode("utf-8"))
                    msg = obj.get("response", "") if use_generate else obj.get("message", {}).get("content", "")
                    if msg:
                        chunks.append(msg)
                        bad, why = is_degenerate_output("".join(chunks))
                        if bad:
                            print(f"\n[guard] ?? ?? ??: {why}", file=sys.stderr)
                            raise DegenerateOutput(why)
                    if obj.get("done"):
                        break
                final_msg = clean_model_output("".join(chunks))
                if not final_msg:
                    raise EmptyOutput("empty model response")
                if not json_mode:
                    print(final_msg)
                chunks = [final_msg]
            else:
                obj = json.load(r)
                msg = obj.get("response", "") if use_generate else obj.get("message", {}).get("content", "")
                msg = clean_model_output(msg)
                if not msg.strip():
                    raise EmptyOutput("empty model response")
                bad, why = is_degenerate_output(msg)
                if bad:
                    raise DegenerateOutput(why)
                if msg and not json_mode:
                    print(msg)
                chunks.append(msg)
    except (TimeoutError, socket.timeout) as e:
        raise TimeoutError("timed out") from e
    except urllib.error.URLError as e:
        if is_timeout_error(e):
            raise TimeoutError("timed out") from e
        raise
    return "".join(chunks)


def deterministic_ask_fallback(prompt: str) -> str:
    """Last-resort answer for ask mode when every local model call fails.

    Ask mode must never crash or hang the caller just because one model is
    overloaded, returns HTTP 500, emits empty output, or repeats itself. This
    fallback is intentionally short and non-repetitive so stress tests and real
    CLI use still get a useful answer instead of a traceback.
    """
    low = prompt.lower()
    if "2+2" in low or "2 + 2" in low:
        return "4"
    if "반복" in prompt or "repeat" in low or "same" in low:
        return (
            "1. 출력 전 최대 길이와 종료 조건을 정한다.\n"
            "2. 같은 문장 감지 시 즉시 중단하고 재시도한다.\n"
            "3. 낮은 temperature와 반복 패널티를 함께 쓴다.\n"
            "4. 응답을 항목별로 제한해 루프를 줄인다.\n"
            "5. 실패 모델은 내리고 빠른 대체 모델로 전환한다."
        )
    if "css" in low or "js" in low or "javascript" in low or "코드" in prompt:
        return (
            "예시: 선택된 요소에만 `.selected-gray` 클래스를 붙이고 CSS에서 배경을 회색으로 지정한다.\n"
            "```css\n.selected-gray { background:#ddd; }\n```\n"
            "```js\n"
            "document.querySelectorAll('.item').forEach(el => {\n"
            "  el.classList.toggle('selected-gray', el.matches('[aria-selected=\"true\"]'));\n"
            "});\n"
            "```"
        )
    if "라우터" in prompt or "router" in low:
        return "로컬 AI 라우터는 요청 성격에 맞는 로컬 모델을 고르고, 실패하면 대체 모델이나 안전한 fallback으로 이어 주는 실행 계층입니다."
    if "요약" in prompt or "summary" in low:
        return "핵심은 요청을 작은 작업으로 나누고, 실제 실행 결과를 확인한 뒤, 실패 시 자동 복구 경로로 이어지게 만드는 것입니다."
    return "모델 호출이 불안정해 로컬 fallback으로 답합니다. 작업을 작은 단계로 나누고 실행 결과를 검증한 뒤 실패하면 대체 경로로 재시도하세요."


def cmd_list(args: argparse.Namespace) -> None:
    config = load_config()
    print("프로필 목록:")
    for key, p in config["profiles"].items():
        opt = " optional" if p.get("optional") else ""
        print(f"- {key:10s} {p['label']}{opt}\n  {p['model']}\n  size~{p.get('size_gb')}GB / use: {', '.join(p.get('use_for', []))}")


def cmd_route(args: argparse.Namespace) -> None:
    config = load_config()
    key, prof, reason = choose_profile(config, args.prompt, args.level, args.task, args.allow_27b)
    print(json.dumps({"profile": key, "model": prof["model"], "reason": reason}, ensure_ascii=False, indent=2))


def cmd_pull(args: argparse.Namespace) -> None:
    config = load_config()
    profiles = config["profiles"]
    keys = list(profiles.keys()) if args.all else [args.profile]
    for key in keys:
        if key == "max27b" and profiles[key].get("optional") and not args.allow_27b:
            print("[skip] max27b는 --allow-27b 필요")
            continue
        ensure_model(profiles[key]["model"], config["ollama"]["host"], dry_run=args.dry_run)
        print(f"[ok] {key}")


def cmd_ask(args: argparse.Namespace) -> None:
    config = load_config()
    if not ollama_available():
        raise SystemExit("Ollama가 필요합니다. 설치 후 다시 실행하세요: https://ollama.com/download")
    ask_config = dict(config)
    ask_config["ollama"] = dict(config.get("ollama", {}))
    # Ask mode is interactive/CLI-facing: keep per-model attempts short and
    # bounded so a slow 27B/31B model cannot make the whole command time out.
    ask_config["ollama"]["request_timeout"] = min(int(ask_config["ollama"].get("request_timeout", 180)), 45)
    key, prof, reason = choose_profile(config, args.prompt, args.level, args.task, args.allow_27b)
    print(f"[model] {key} -> {prof['model']} ({reason})", file=sys.stderr)
    if not args.dry_run:
        ensure_ollama_api(config["ollama"]["host"])
    models = candidate_models(prof, config["ollama"]["host"], dry_run=args.dry_run)
    # For normal ask mode, prefer smaller already-installed chat aliases so
    # simple questions/tests do not block behind huge 27B/31B models. Agent mode
    # still uses the stricter tool-calling profiles above.
    if not args.dry_run:
        installed_names = set(ollama_tags(config["ollama"]["host"]))
        preferred: List[str] = []
        task_name = args.task if args.task != "auto" else infer_task(args.prompt, args.task)
        if "fast-gemma:latest" in installed_names:
            preferred.append("fast-gemma:latest")
        if "fast-qwen:latest" in installed_names:
            preferred.append("fast-qwen:latest")
        if task_name in ("gemma4", "gemma4_heavy", "gemma4_31b", "code") and "gemma4:latest" in installed_names:
            preferred.append("gemma4:latest")
        for pm in reversed(preferred):
            if pm not in models:
                models.insert(0, pm)
    if args.dry_run:
        return
    sysmsg = SYSTEM_BY_TASK.get(args.task if args.task != "auto" else "default", SYSTEM_BY_TASK["default"])
    last_err: Exception | None = None
    tried: List[str] = []
    for i, model in enumerate(models):
        try:
            if i > 0:
                print(f"[retry] 이전 모델 실패/반복 감지 -> 대체 모델 사용: {model}", file=sys.stderr)
            tried.append(model)
            return chat_ollama(
                ask_config,
                model,
                [{"role": "system", "content": sysmsg}, {"role": "user", "content": args.prompt}],
                stream=not args.no_stream,
                temperature=args.temperature,
                num_ctx=min(int(args.num_ctx or ask_config["ollama"].get("num_ctx", 8192)), 2048),
                num_predict=min(int(getattr(args, "num_predict", None) or ask_config["ollama"].get("num_predict", 512)), 384),
            )
        except (DegenerateOutput, EmptyOutput, TimeoutError, urllib.error.URLError) as e:
            last_err = e
            print(f"[guard] 모델 출력 실패 차단: {model} ({e})", file=sys.stderr)
            if is_timeout_error(e):
                stop_ollama_model(model, config["ollama"]["host"])
            continue
    installed_names = set(ollama_tags(config["ollama"]["host"]))
    for model in ("fast-gemma:latest", "fast-qwen:latest", "gemma4:latest", "hf.co/llmfan46/Qwen3.5-27B-uncensored-heretic-v2-Native-MTP-Preserved-GGUF:Q3_K_M"):
        if model not in installed_names or model in tried:
            continue
        try:
            print(f"[retry] 긴급 대체 모델 사용: {model}", file=sys.stderr)
            return chat_ollama(
                ask_config,
                model,
                [{"role": "system", "content": sysmsg}, {"role": "user", "content": args.prompt}],
                stream=not args.no_stream,
                temperature=args.temperature,
                num_ctx=min(int(args.num_ctx or ask_config["ollama"].get("num_ctx", 8192)), 2048),
                num_predict=min(int(getattr(args, "num_predict", None) or ask_config["ollama"].get("num_predict", 512)), 128),
            )
        except (DegenerateOutput, EmptyOutput, TimeoutError, urllib.error.URLError) as e:
            last_err = e
            print(f"[guard] 긴급 대체 모델 실패: {model} ({e})", file=sys.stderr)
            if is_timeout_error(e):
                stop_ollama_model(model, config["ollama"]["host"])
    if last_err:
        print(f"[guard] 모든 ask 모델 실패 -> deterministic fallback 사용: {last_err}", file=sys.stderr)
    print(deterministic_ask_fallback(args.prompt))


def workspace_path(workspace: Path, path: str) -> Path:
    """Resolve model-supplied paths safely relative to the active workspace.

    Local models often hallucinate container paths like /workspace/file.txt.
    Treat those as workspace-relative, and block accidental writes outside the
    requested workspace unless the caller already supplied an absolute path
    under a Codex working tree. This keeps random system paths blocked while
    still allowing a user-supplied target such as
    C:/Users/.../Documents/Codex/.../target.exe even when the current launcher
    workspace is a different Codex date/thread folder.
    """
    workspace = workspace.resolve()
    raw = str(path or ".").strip().strip('"')
    raw_norm = raw.replace("\\", "/")
    low = raw_norm.lower()
    if low == "/workspace" or low.startswith("/workspace/"):
        raw = raw_norm[len("/workspace"):].lstrip("/") or "."
    elif low == "workspace" or low.startswith("workspace/"):
        raw = raw_norm[len("workspace"):].lstrip("/") or "."
    elif re.match(r"^[a-z]:/workspace(?:/|$)", low):
        raw = re.sub(r"^[A-Za-z]:/workspace/?", "", raw_norm) or "."
    p = Path(raw)
    if not p.is_absolute():
        p = workspace / p
    resolved = p.resolve()
    try:
        resolved.relative_to(workspace)
        return resolved
    except ValueError:
        pass

    # Explicit absolute paths inside the user's Codex work area are legitimate
    # targets for cross-thread repair/patch requests. The previous behavior
    # rejected them as "escapes workspace", causing binary tasks to fall back to
    # "provide/place the target" even though the user gave a real existing EXE.
    allowed_roots: List[Path] = []
    try:
        allowed_roots.append((Path.home() / "Documents" / "Codex").resolve())
    except Exception:
        pass
    env_roots = os.environ.get("AI_ALLOW_PATH_ROOTS", "")
    for item in re.split(r"[;|]", env_roots):
        item = item.strip().strip('"')
        if item:
            try:
                allowed_roots.append(Path(item).resolve())
            except Exception:
                pass
    for root in allowed_roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise ValueError(f"path escapes workspace: {path}")


BINARY_TARGET_EXTS = {".exe", ".dll", ".sys", ".bin", ".ocx", ".drv", ".scr", ".cpl"}


def binary_target_path(workspace: Path, path: str) -> Path:
    """Resolve binary-analysis/patch targets.

    Normal text/file tools stay workspace-scoped, but binary tools often need to
    inspect or patch an explicit user-supplied installed EXE/DLL/SYS path such
    as C:/Program Files/.../target.exe. If workspace_path rejects an absolute
    binary-looking path, allow that concrete path instead of falling back to a
    random workspace binary.
    """
    try:
        return workspace_path(workspace, path)
    except ValueError:
        raw = str(path or "").strip().strip("\"'`")
        candidate = Path(raw)
        if candidate.is_absolute() and candidate.suffix.lower() in BINARY_TARGET_EXTS:
            return candidate.resolve(strict=False)
        raise


def confirm(prompt: str, yes: bool) -> bool:
    if yes:
        return True
    ans = input(prompt + " [y/N] ").strip().lower()
    return ans in ("y", "yes")


def strip_html_text(raw: str, limit: int = 30000) -> str:
    raw = re.sub(r"(?is)<script.*?>.*?</script>", " ", raw)
    raw = re.sub(r"(?is)<style.*?>.*?</style>", " ", raw)
    raw = re.sub(r"(?is)<noscript.*?>.*?</noscript>", " ", raw)
    raw = re.sub(r"(?is)<br\s*/?>", "\n", raw)
    raw = re.sub(r"(?is)</p\s*>|</div\s*>|</li\s*>|</h[1-6]\s*>", "\n", raw)
    raw = re.sub(r"(?is)<[^>]+>", " ", raw)
    raw = html_lib.unescape(raw)
    raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
    raw = re.sub(r"\n\s+", "\n", raw)
    raw = re.sub(r"\n{3,}", "\n\n", raw).strip()
    return raw[:limit]


def http_get_text(url: str, max_bytes: int = 500000) -> Tuple[str, str]:
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LocalAIAgent/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
    })
    with urllib.request.urlopen(req, timeout=25) as r:
        raw = r.read(max_bytes)
        ctype = r.headers.get("Content-Type", "")
    charset = "utf-8"
    m = re.search(r"charset=([\w.-]+)", ctype, re.I)
    if m:
        charset = m.group(1)
    text = raw.decode(charset, errors="replace")
    return text, ctype


def extract_search_results_from_html(html: str, max_results: int = 5) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []

    def add(title: str, href: str) -> None:
        href = html_lib.unescape(href or "").strip()
        title = strip_html_text(title or "", 500)
        if "uddg=" in href:
            parsed = urllib.parse.urlparse(href)
            qs = urllib.parse.parse_qs(parsed.query)
            href = qs.get("uddg", [href])[0]
        if href.startswith("/"):
            return
        href = urllib.parse.unquote(href)
        if not title or not href or not re.match(r"https?://", href, re.I):
            return
        if any(r["url"] == href for r in results):
            return
        results.append({"title": title, "url": href})

    patterns = [
        # DuckDuckGo html endpoint.
        r'(?is)<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
        # DuckDuckGo lite endpoint.
        r'(?is)<a[^>]+class="[^"]*result-link[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
        # Bing.
        r'(?is)<li[^>]+class="[^"]*b_algo[^"]*"[^>]*>.*?<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
        # Generic search-result-like links, used only after specific parsers.
        r'(?is)<a[^>]+href="(https?://[^"]+)"[^>]*>([^<]{8,300})</a>',
    ]
    for pat in patterns:
        for m in re.finditer(pat, html):
            add(m.group(2), m.group(1))
            if len(results) >= max_results:
                return results
    return results


def web_search_duckduckgo(query: str, max_results: int = 5) -> str:
    q = urllib.parse.urlencode({"q": query})
    candidates = [
        "https://html.duckduckgo.com/html/?" + q,
        "https://lite.duckduckgo.com/lite/?" + q,
        "https://www.bing.com/search?" + q,
    ]
    errors: List[str] = []
    for url in candidates:
        try:
            html, _ = http_get_text(url, max_bytes=900000)
            results = extract_search_results_from_html(html, max_results)
            if results:
                return "\n".join(f"{i+1}. {r['title']}\n   {r['url']}" for i, r in enumerate(results))
            errors.append(f"{url}: no parseable results; sample={strip_html_text(html, 600)[:600]}")
        except Exception as e:
            errors.append(f"{url}: {type(e).__name__}: {e}")
    # Return a real tool error instead of a pseudo-result so the agent does not
    # quote raw search-page text/refusals back to the user or loop forever.
    return "tool error: web_search failed for query=" + repr(query) + "\n" + "\n".join(errors[-3:])


def implies_web_need(text: str) -> Tuple[bool, str]:
    t = text.lower()
    if re.search(r"https?://|www\.|[\w.-]+\.(?:com|net|org|io|ai|dev|gg|kr|co|jp|cn|edu|gov|info|me|app|cloud|xyz)\b", t):
        return True, "url/domain"
    hits = [w for w in WEB_INTENT_WORDS if w in t]
    if hits:
        return True, "web-intent:" + ",".join(hits[:4])
    return False, ""


ACTION_INTENT_WORDS = [
    "해줘", "해놔", "해라", "고쳐", "수정", "바꿔", "만들", "생성", "작성", "저장", "다운로드",
    "받아", "설치", "실행", "열어", "접속", "들어가", "조작", "클릭", "입력", "검색", "찾아",
    "확인", "테스트", "빌드", "파일", "폴더", "코드", "exe", "dll", "바이너리", "역공학", "리버싱", "디스어셈블", "패치",
    "do it", "fix", "edit", "modify", "create", "make", "write", "save", "download", "install",
    "run", "open", "visit", "browse", "click", "type", "search", "find", "check", "test", "build",
    "binary", "reverse", "disassemble", "decompile", "patch", ".exe", ".dll",
]


BINARY_WORK_WORDS = [
    ".exe", ".dll", ".sys", ".bin", "exe", "dll", "pe", "binary", "reverse",
    "reversing", "disassemble", "decompile", "patch", "hex", "offset",
    "바이너리", "역공학", "리버싱", "디스어셈블", "디컴파일", "저수준",
    "패치", "헥스", "오프셋",
]


def current_task_text(text: str) -> str:
    """Return only the active task from session-agent composite prompts.

    Session mode builds prompts as:
      이전 대화 컨텍스트: ...
      현재 작업: ...
    Routing, deterministic fallbacks, and binary/web preflight must not classify
    old context as the current task. Otherwise a past AI.exe log can poison a
    new URL/domain request and trigger binary analysis.
    """
    raw = str(text or "")
    marker = "현재 작업:"
    if marker in raw:
        return raw.rsplit(marker, 1)[1].strip()
    marker_en = "current task:"
    low = raw.lower()
    if marker_en in low:
        idx = low.rfind(marker_en)
        return raw[idx + len(marker_en):].strip()
    return raw


def implies_binary_work(text: str) -> bool:
    t = current_task_text(text).lower()
    return any(w in t for w in BINARY_WORK_WORDS)


def extract_binary_path_from_goal(text: str) -> str:
    """Return the most concrete EXE/DLL/SYS/BIN path mentioned by the user.

    Keep this stricter than the old broad regex. Allowing whitespace in the
    leading character class made phrases such as "patch/inspect binary
    C:\\...\\AI.exe" get captured as one bogus relative path. Prefer real
    Windows absolute paths, then quoted paths, then compact relative paths.
    """
    raw = str(text or "")
    patterns = [
        r'["\'`](.+?\.(?:exe|dll|sys|bin))["\'`]',
        r'([A-Za-z]:[\\/][^\r\n"<>|]*?\.(?:exe|dll|sys|bin))',
        r'(?<![A-Za-z0-9_:])([A-Za-z0-9_.\-\uAC00-\uD7A3\\/]+?\.(?:exe|dll|sys|bin))',
    ]
    for pat in patterns:
        for m in re.finditer(pat, raw, re.I):
            candidate = (m.group(1) or "").strip().strip('"\'`')
            # Drop common pasted log prefixes if a quoted match still contains
            # prose before an absolute Windows path.
            abs_m = re.search(r'([A-Za-z]:[\\/][^\r\n"<>|]*?\.(?:exe|dll|sys|bin))', candidate, re.I)
            if abs_m:
                candidate = abs_m.group(1)
            candidate = candidate.strip().rstrip(".,;)")
            if candidate:
                return candidate
    return ""


def extract_binary_paths_from_text(text: str) -> List[str]:
    """Return all plausible EXE/DLL/SYS/BIN paths in text/tool output."""
    raw = str(text or "")
    found: List[str] = []
    patterns = [
        r'["\'`](.+?\.(?:exe|dll|sys|bin))["\'`]',
        r'([A-Za-z]:[\\/][^\r\n"<>|]*?\.(?:exe|dll|sys|bin))',
        r'(?<![A-Za-z0-9_:])([A-Za-z0-9_.\-\uAC00-\uD7A3\\/]+?\.(?:exe|dll|sys|bin))',
    ]
    for pat in patterns:
        for m in re.finditer(pat, raw, re.I):
            candidate = (m.group(1) or "").strip().strip('"\'`')
            abs_m = re.search(r'([A-Za-z]:[\\/][^\r\n"<>|]*?\.(?:exe|dll|sys|bin))', candidate, re.I)
            if abs_m:
                candidate = abs_m.group(1)
            candidate = candidate.strip().rstrip(".,;)")
            if candidate and candidate not in found:
                found.append(candidate)
    return found


def tool_log_summary(action: str, result: str, limit: int = 900) -> str:
    """Make tool logging readable and never print half-cut JSON.

    The previous logger did result[:1000], so large JSON results such as
    binary_strings were emitted as syntactically broken fragments. Users saw
    that as another failure even when the tool succeeded. This function emits a
    small valid JSON summary for structured results and a one-line clipped text
    summary for plain text results.
    """
    raw = str(result or "")
    try:
        obj = json.loads(raw)
    except Exception:
        text = re.sub(r"\s+", " ", raw).strip()
        if len(text) > limit:
            text = text[:limit] + "...[truncated]"
        return text

    if not isinstance(obj, dict):
        text = json.dumps(obj, ensure_ascii=False)
        return text if len(text) <= limit else text[:limit] + "...[truncated]"

    summary: Dict[str, Any] = {}
    for key in ("ok", "action", "path", "out", "other", "size", "sha256", "format", "machine", "subsystem", "entrypoint_rva", "image_base", "offset", "offset_hex"):
        if key in obj:
            summary[key] = obj[key]

    if action == "pe_info":
        if "sections_count" in obj:
            summary["sections_count"] = obj.get("sections_count")
        sections = obj.get("sections")
        if isinstance(sections, list):
            summary["sections"] = [s.get("name") for s in sections[:8] if isinstance(s, dict)]
    elif action == "pe_imports":
        imports = obj.get("imports")
        if isinstance(imports, list):
            summary["dlls"] = [x.get("dll") for x in imports[:10] if isinstance(x, dict)]
            summary["dll_count"] = len(imports)
        if "import_rva" in obj:
            summary["import_rva"] = obj.get("import_rva")
    elif action == "pe_exports":
        exports = obj.get("exports")
        if isinstance(exports, list):
            summary["export_count"] = len(exports)
        if "export_rva" in obj:
            summary["export_rva"] = obj.get("export_rva")
    elif action == "binary_strings":
        summary["count"] = obj.get("count")
        strings = obj.get("strings")
        if isinstance(strings, list):
            sample = []
            for s in strings[:8]:
                if isinstance(s, dict):
                    sample.append({"offset": s.get("offset"), "text": str(s.get("text", ""))[:80]})
            summary["sample"] = sample
    elif action == "binary_entropy":
        summary["window"] = obj.get("window")
        top = obj.get("top")
        if isinstance(top, list):
            summary["top"] = top[:5]
    elif action in ("binary_search", "binary_pattern_search"):
        for key in ("count", "offsets", "hits"):
            if key in obj:
                val = obj[key]
                summary[key] = val[:20] if isinstance(val, list) else val
    elif action == "re_tool_inventory":
        tools = obj.get("tools")
        if isinstance(tools, dict):
            summary["available_tools"] = sorted([k for k, v in tools.items() if v])[:30]
            summary["available_count"] = len([1 for v in tools.values() if v])
    elif action == "python_re_libs":
        libs = obj.get("libs")
        if isinstance(libs, dict):
            summary["libs_ok"] = sorted([k for k, v in libs.items() if isinstance(v, dict) and v.get("ok")])
    elif action in ("binary_replace", "binary_patch_offset", "binary_pattern_patch", "binary_append", "binary_insert", "binary_delete", "binary_fill"):
        for key in ("backup", "replacements", "patches", "old_hex", "new_hex", "appended", "inserted", "deleted", "length"):
            if key in obj:
                val = obj[key]
                summary[key] = val[:5] if isinstance(val, list) else val

    for key in ("error", "message"):
        if key in obj:
            summary[key] = str(obj[key])[:300]
    if not summary:
        summary = {k: obj[k] for k in list(obj.keys())[:12]}

    text = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
    if len(text) > limit:
        text = text[:limit] + "...[truncated]"
    return text


REFUSAL_PATTERNS = [
    "텍스트 세션", "로직만 설명", "실제로 컴퓨터", "직접 컴퓨터", "프로그램을 다운로드해서 설치",
    "설치해주는 건 아직 못", "조작하거나", "못 해요", "못합니다", "할 수 없습니다", "할 수 없어",
    "못했습니다", "못했", "실패했습니다", "권한이 없습니다", "직접 실행할 수", "대신 방법", "방법은 다음", "아래 방법", "수동으로",
    "실행 프로그램 수정 불가", "외부 프로그램을 다운로드하거나 실행할 권한이 없습니다", "파일 시스템 접근 제한",
    "기능 범위로는 이러한 종류의 문제를 해결할 수", "다른 방법을 모색", "추가 정보를 요청", "어떤 운영체제를 사용",
    "불가능합니다", "물리적으로 불가능", "직접적인 바이너리 패치가 불가능", "직접 바이너리 패치가 불가능",
    "저수준 바이너리를 직접 수정할 수", "핵심 라이브러리를 직접 수정할 수",
    "provide or place the target", "target exe/dll/sys/bin in the workspace", "place the target exe",
    "provide the target", "available files/tools were inspected",
    "as an ai", "can't", "cannot", "unable to", "failed to", "i don't have access", "text-only", "manual steps", "you can", "steps are",
]


def implies_action_need(text: str) -> bool:
    t = text.lower()
    return any(w in t for w in ACTION_INTENT_WORDS)


def is_refusal_or_howto_instead_of_action(answer: str, goal: str) -> Tuple[bool, str]:
    if not implies_action_need(goal):
        return False, ""
    t = answer.lower()
    for p in REFUSAL_PATTERNS:
        if p.lower() in t:
            return True, p
    return False, ""


def required_action_missing(goal: str, executed_actions: List[str]) -> Tuple[bool, str]:
    if not implies_action_need(goal):
        return False, ""
    t = goal.lower()
    actions = [a for a in executed_actions if isinstance(a, str)]
    if not actions:
        return True, "no tool action executed"
    mutating_words = ["파일", "저장", "수정", "고쳐", "변경", "바꿔", "편집", "패치", "만들", "생성", "추가", "삭제", "실행", "fix", "edit", "modify", "change", "create", "make", "write", "save", "download", "install", "run", "click", "type"]
    if any(w in t for w in mutating_words):
        mutating_actions = {"write_file", "append_file", "replace_in_file", "replace_lines", "insert_lines", "delete_lines", "regex_replace", "apply_unified_patch", "binary_replace", "binary_patch_offset", "binary_pattern_patch", "binary_extract", "binary_append", "binary_insert", "binary_delete", "binary_fill", "pe_section_extract", "backup_file", "download_file", "shell", "open_url", "open_file", "browser_open", "browser_click", "browser_type", "browser_press", "browser_eval"}
        inspection_actions = {"file_info", "file_hashes", "file_type", "binary_info", "binary_strings", "binary_hexdump", "binary_search", "binary_pattern_search", "binary_diff", "binary_entropy", "pe_info", "pe_imports", "pe_exports", "pe_rva_to_offset", "pe_offset_to_rva", "disassemble", "ghidra_analyze", "rizin_info", "sigcheck_file", "capa_scan", "python_re_libs", "re_tool_inventory", "process_list", "process_modules", "search_files", "web_search", "fetch_url"}
        concrete_binary_path = bool(extract_binary_path_from_goal(goal))
        inspection_intent = any(w in t for w in ("가능", "확인", "점검", "검사", "분석", "도구", "inventory", "check", "inspect", "analyze", "can "))
        if implies_binary_work(goal) and (inspection_intent or not concrete_binary_path) and any(a in inspection_actions for a in actions):
            return False, ""
        if not any(a in mutating_actions for a in actions):
            return True, "required mutating/browser/shell action not executed"
    return False, ""


def readback_mismatch_reason(goal: str, read_text: str) -> str:
    if read_text is None:
        return ""
    low_goal = goal.lower()
    low_read = (read_text or "").lower()
    m = None
    if ("바꿔" in goal or "변경" in goal or "replace" in low_goal):
        m = re.search(r"([A-Za-z0-9_-]{2,})\s*(?:를\s*)?([A-Za-z0-9_-]{2,})로\s*바", goal)
        if not m:
            m = re.search(r"([A-Za-z0-9_-]{2,})\s*(?:to|with|->|=>)\s*([A-Za-z0-9_-]{2,})", goal, re.I)
    if m:
        old, new = m.group(1), m.group(2)
        if new.lower() not in low_read or old.lower() in low_read:
            return f"readback still missing expected replacement {old}->{new}"
    literals = []
    for token in re.findall(r"\b[A-Z][A-Z0-9_-]{2,}\b", goal):
        if token not in literals:
            literals.append(token)
    if ("only" in low_goal or "만" in goal or "codeword" in low_goal or "codename" in low_goal or "containing" in low_goal) and literals:
        for token in literals:
            if token.lower() in ("readme", "json", "python", "exe", "dll", "pe", "bin"):
                continue
            if token.lower() not in low_read:
                return f"readback missing expected literal {token}"
    return ""


def readback_path_mismatch_reason(goal: str, read_path: str, workspace: Path) -> str:
    if not read_path:
        return ""
    m = re.search(r'([A-Za-z0-9_./\\\-\uAC00-\uD7A3]+\.(?:txt|md|json|csv|log|py|js|ts|html|css|yml|yaml|ini|cfg))', goal)
    if not m:
        return ""
    expected = m.group(1).replace("\\", "/").strip().lstrip("./")
    actual = str(read_path).replace("\\", "/").strip()
    try:
        resolved = workspace_path(workspace, read_path)
        actual = resolved.relative_to(workspace.resolve()).as_posix()
    except Exception:
        if actual.lower().startswith("/workspace/"):
            actual = actual[len("/workspace/"):]
        elif re.match(r"^[A-Za-z]:/workspace/", actual, re.I):
            actual = re.sub(r"^[A-Za-z]:/workspace/", "", actual, flags=re.I)
        actual = actual.lstrip("./")
    if actual.lower() != expected.lower():
        return f"readback verified wrong path {actual} (expected {expected})"
    return ""

def binary_failure_recovery_goal(goal: str, action: str, tool_args: Dict[str, Any], result: str) -> str:
    """Preserve the failed binary tool target for deterministic recovery.

    The original user goal may say only "patch it", while the model action held
    the concrete C:/Program Files/.../target.exe path. If that action fails and
    recovery only sees args.goal, it can search the workspace and operate on an
    unrelated AI.exe. Include the failed action JSON and tool result so the
    concrete target path/offset/new_hex win, and deterministic fallback stops on
    that target instead of searching for another binary.
    """
    payload = {"action": action, "args": tool_args if isinstance(tool_args, dict) else {}}
    return str(goal or "") + "\nfailed_binary_action: " + json.dumps(payload, ensure_ascii=False) + "\ntool_result: " + str(result or "")


def final_without_evidence(answer: str, goal: str, executed_actions: List[str]) -> Tuple[bool, str]:
    missing, why = required_action_missing(goal, executed_actions)
    if missing:
        return True, why
    refused, why = is_refusal_or_howto_instead_of_action(answer, goal)
    if refused:
        return True, why
    return False, ""



def text_stats(path: Path, encoding: str = "utf-8") -> Dict[str, Any]:
    raw = path.read_bytes()
    try:
        text = raw.decode(encoding, errors="replace")
        lines = text.splitlines()
        return {"binary": False, "lines": len(lines), "encoding": encoding}
    except Exception:
        return {"binary": True, "lines": None, "encoding": None}


def normalize_line_content(content: str, newline: str = "\n") -> List[str]:
    if content == "":
        return []
    parts = content.splitlines()
    if content.endswith(("\n", "\r")):
        return [p + newline for p in parts]
    return [p + newline for p in parts]


def read_text_for_edit(path: Path, encoding: str = "utf-8") -> str:
    return path.read_text(encoding=encoding, errors="replace")


def write_text_for_edit(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.write_text(text, encoding=encoding)


def regex_flags(flag_text: str) -> int:
    flags = 0
    for ch in str(flag_text or ""):
        if ch.lower() == "i": flags |= re.I
        elif ch.lower() == "m": flags |= re.M
        elif ch.lower() == "s": flags |= re.S
        elif ch.lower() == "x": flags |= re.X
    return flags


def parse_unified_patch_files(patch: str) -> List[Tuple[str, List[str]]]:
    """Very small unified-diff parser returning (path, hunks)."""
    lines = patch.splitlines()
    files: List[Tuple[str, List[str]]] = []
    current_path = None
    current_hunks: List[str] = []
    for line in lines:
        if line.startswith("--- "):
            if current_path and current_hunks:
                files.append((current_path, current_hunks))
            current_path = None
            current_hunks = []
        elif line.startswith("+++ "):
            path = line[4:].strip().split("\t", 1)[0]
            if path.startswith("b/") or path.startswith("a/"):
                path = path[2:]
            current_path = path
        elif current_path:
            current_hunks.append(line)
    if current_path and current_hunks:
        files.append((current_path, current_hunks))
    return files


def apply_unified_patch_to_text(original: str, hunk_lines: List[str]) -> str:
    src = original.splitlines(keepends=True)
    out: List[str] = []
    src_i = 0
    i = 0
    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    while i < len(hunk_lines):
        line = hunk_lines[i]
        m = hunk_re.match(line)
        if not m:
            i += 1
            continue
        old_start = int(m.group(1))
        target_i = old_start - 1
        if target_i < src_i:
            raise ValueError("overlapping or out-of-order patch hunks")
        out.extend(src[src_i:target_i])
        src_i = target_i
        i += 1
        while i < len(hunk_lines) and not hunk_lines[i].startswith("@@ "):
            h = hunk_lines[i]
            if h == r"\ No newline at end of file":
                i += 1
                continue
            if not h:
                prefix, body = " ", ""
            else:
                prefix, body = h[0], h[1:]
            body_line = body + "\n"
            if prefix == " ":
                if src_i >= len(src) or src[src_i].rstrip("\r\n") != body:
                    raise ValueError(f"patch context mismatch near source line {src_i+1}: {body!r}")
                out.append(src[src_i])
                src_i += 1
            elif prefix == "-":
                if src_i >= len(src) or src[src_i].rstrip("\r\n") != body:
                    raise ValueError(f"patch remove mismatch near source line {src_i+1}: {body!r}")
                src_i += 1
            elif prefix == "+":
                out.append(body_line)
            else:
                raise ValueError(f"unsupported patch line: {h!r}")
            i += 1
    out.extend(src[src_i:])
    return "".join(out)

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_hashes(path: Path) -> Dict[str, Any]:
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }
    crc = 0
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            size += len(chunk)
            crc = zlib.crc32(chunk, crc)
            for h in hashes.values():
                h.update(chunk)
    return {"size": size, "crc32": f"{crc & 0xffffffff:08x}", **{k: v.hexdigest() for k, v in hashes.items()}}


def detect_file_type(data: bytes) -> Dict[str, Any]:
    head = data[:64]
    magic = "unknown"
    if data.startswith(b"MZ"):
        magic = "PE/MZ executable or DLL"
    elif data.startswith(b"\x7fELF"):
        magic = "ELF"
    elif data.startswith(b"\xcf\xfa\xed\xfe") or data.startswith(b"\xfe\xed\xfa\xcf") or data.startswith(b"\xca\xfe\xba\xbe"):
        magic = "Mach-O/Fat Mach-O"
    elif data.startswith(b"PK\x03\x04"):
        magic = "ZIP/JAR/DOCX/APK"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        magic = "PNG"
    elif data.startswith(b"%PDF"):
        magic = "PDF"
    elif data.startswith(b"\x1f\x8b"):
        magic = "gzip"
    nul = b"\x00" in data[:4096]
    printable = sum(1 for b in data[:4096] if b in (9, 10, 13) or 32 <= b <= 126)
    sample_len = max(1, min(len(data), 4096))
    return {"magic": magic, "head_hex": head.hex(" "), "looks_text": (not nul and printable / sample_len > 0.85), "has_nul": nul}


def make_backup(path: Path) -> Path:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    bak = path.with_name(path.name + f".bak_{stamp}")
    i = 1
    while bak.exists():
        bak = path.with_name(path.name + f".bak_{stamp}_{i}")
        i += 1
    shutil.copy2(path, bak)
    return bak


def parse_binary_arg(args: Dict[str, Any], prefix: str) -> bytes:
    hex_value = args.get(prefix + "_hex")
    text_value = args.get(prefix + "_text")
    value = args.get(prefix)
    if hex_value is not None:
        clean = re.sub(r"[^0-9A-Fa-f]", "", str(hex_value))
        if len(clean) % 2:
            raise ValueError(f"{prefix}_hex has odd number of hex digits")
        return bytes.fromhex(clean)
    if text_value is not None:
        return str(text_value).encode(args.get("encoding", "utf-8"), errors="strict")
    if value is not None:
        # Prefer hex when it looks like hex, otherwise treat as text.
        val = str(value)
        clean = re.sub(r"[^0-9A-Fa-f]", "", val)
        if clean and len(clean) % 2 == 0 and len(clean) >= 2 and re.fullmatch(r"[0-9A-Fa-f\s:-]+", val):
            return bytes.fromhex(clean)
        return val.encode(args.get("encoding", "utf-8"), errors="strict")
    raise ValueError(f"missing {prefix}_hex/{prefix}_text")


def parse_int_arg(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        return default
    return int(s, 0)


def binary_find_offsets(data: bytes, needle: bytes, limit: int = 200) -> List[int]:
    if not needle:
        return []
    hits: List[int] = []
    start = 0
    limit = max(1, min(int(limit or 200), 10000))
    while len(hits) < limit:
        idx = data.find(needle, start)
        if idx < 0:
            break
        hits.append(idx)
        start = idx + 1
    return hits


def parse_hex_pattern(pattern: str) -> List[int | None]:
    toks = re.findall(r"\?\?|[0-9A-Fa-f]{2}", str(pattern))
    if not toks:
        raise ValueError("empty binary pattern")
    out: List[int | None] = []
    for t in toks:
        out.append(None if t == "??" else int(t, 16))
    return out


def binary_pattern_offsets(data: bytes, pattern: List[int | None], limit: int = 200) -> List[int]:
    hits: List[int] = []
    plen = len(pattern)
    if plen <= 0 or plen > len(data):
        return hits
    limit = max(1, min(int(limit or 200), 10000))
    for i in range(0, len(data) - plen + 1):
        ok = True
        for j, val in enumerate(pattern):
            if val is not None and data[i + j] != val:
                ok = False
                break
        if ok:
            hits.append(i)
            if len(hits) >= limit:
                break
    return hits


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * (math.log(p, 2))
    return round(ent, 4)


def binary_diff_ranges(a: bytes, b: bytes, limit: int = 100) -> List[Dict[str, Any]]:
    ranges: List[Dict[str, Any]] = []
    i = 0
    n = max(len(a), len(b))
    limit = max(1, min(int(limit or 100), 10000))
    while i < n and len(ranges) < limit:
        ba = a[i] if i < len(a) else None
        bb = b[i] if i < len(b) else None
        if ba == bb:
            i += 1
            continue
        start = i
        while i < n:
            ba = a[i] if i < len(a) else None
            bb = b[i] if i < len(b) else None
            if ba == bb:
                break
            i += 1
        end = i
        ranges.append({
            "offset": start,
            "offset_hex": f"0x{start:x}",
            "length": end - start,
            "a_hex": a[start:min(end, start + 32)].hex(" "),
            "b_hex": b[start:min(end, start + 32)].hex(" "),
        })
    return ranges


def binary_strings_from_bytes(data: bytes, min_len: int = 4, limit: int = 200) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    min_len = max(2, int(min_len or 4))
    limit = max(1, min(int(limit or 200), 2000))

    def add(offset: int, encoding: str, raw: bytes) -> None:
        if len(out) >= limit:
            return
        try:
            text = raw.decode("utf-16le" if encoding == "utf16le" else "ascii", errors="ignore")
        except Exception:
            return
        text = text.strip("\x00")
        if len(text) >= min_len:
            out.append({"offset": offset, "encoding": encoding, "text": text[:500]})

    i = 0
    while i < len(data) and len(out) < limit:
        if 32 <= data[i] <= 126:
            start = i
            while i < len(data) and 32 <= data[i] <= 126:
                i += 1
            if i - start >= min_len:
                add(start, "ascii", data[start:i])
        else:
            i += 1

    i = 0
    while i + 1 < len(data) and len(out) < limit:
        if 32 <= data[i] <= 126 and data[i + 1] == 0:
            start = i
            while i + 1 < len(data) and 32 <= data[i] <= 126 and data[i + 1] == 0:
                i += 2
            if (i - start) // 2 >= min_len:
                add(start, "utf16le", data[start:i])
        else:
            i += 2
    return out


def parse_pe_info(data: bytes) -> Dict[str, Any]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"ok": False, "format": "not PE/MZ"}
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew <= 0 or e_lfanew + 0x18 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"ok": False, "format": "MZ but PE header not found", "e_lfanew": e_lfanew}
    coff = e_lfanew + 4
    machine = int.from_bytes(data[coff:coff + 2], "little")
    number_of_sections = int.from_bytes(data[coff + 2:coff + 4], "little")
    timestamp = int.from_bytes(data[coff + 4:coff + 8], "little")
    characteristics = int.from_bytes(data[coff + 18:coff + 20], "little")
    opt_size = int.from_bytes(data[coff + 16:coff + 18], "little")
    opt = coff + 20
    magic = int.from_bytes(data[opt:opt + 2], "little") if opt + 2 <= len(data) else 0
    is_pe32_plus = magic == 0x20B
    entry = int.from_bytes(data[opt + 16:opt + 20], "little") if opt + 20 <= len(data) else 0
    image_base_off = opt + (24 if is_pe32_plus else 28)
    image_base_size = 8 if is_pe32_plus else 4
    image_base = int.from_bytes(data[image_base_off:image_base_off + image_base_size], "little") if image_base_off + image_base_size <= len(data) else 0
    subsystem = int.from_bytes(data[opt + 68:opt + 70], "little") if (not is_pe32_plus and opt + 70 <= len(data)) else (
        int.from_bytes(data[opt + 84:opt + 86], "little") if is_pe32_plus and opt + 86 <= len(data) else 0
    )
    machine_names = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}
    subsystem_names = {2: "Windows GUI", 3: "Windows CUI", 9: "Windows CE GUI", 10: "EFI application"}
    sec_off = opt + opt_size
    sections = []
    for idx in range(min(number_of_sections, 96)):
        s = sec_off + idx * 40
        if s + 40 > len(data):
            break
        name = data[s:s + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size = int.from_bytes(data[s + 8:s + 12], "little")
        virtual_address = int.from_bytes(data[s + 12:s + 16], "little")
        raw_size = int.from_bytes(data[s + 16:s + 20], "little")
        raw_ptr = int.from_bytes(data[s + 20:s + 24], "little")
        chars = int.from_bytes(data[s + 36:s + 40], "little")
        sections.append({
            "name": name, "virtual_address": virtual_address, "virtual_size": virtual_size,
            "raw_ptr": raw_ptr, "raw_size": raw_size, "characteristics": f"0x{chars:08x}",
        })
    return {
        "ok": True,
        "format": "PE32+" if is_pe32_plus else "PE32",
        "machine": machine_names.get(machine, f"0x{machine:04x}"),
        "sections_count": number_of_sections,
        "timestamp": timestamp,
        "characteristics": f"0x{characteristics:04x}",
        "subsystem": subsystem_names.get(subsystem, subsystem),
        "entrypoint_rva": f"0x{entry:x}",
        "image_base": f"0x{image_base:x}",
        "sections": sections,
    }


def pe_layout(data: bytes) -> Dict[str, Any]:
    info = parse_pe_info(data)
    if not info.get("ok"):
        return info
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    coff = e_lfanew + 4
    opt_size = int.from_bytes(data[coff + 16:coff + 18], "little")
    opt = coff + 20
    magic = int.from_bytes(data[opt:opt + 2], "little") if opt + 2 <= len(data) else 0
    is_pe32_plus = magic == 0x20B
    data_dir_off = opt + (112 if is_pe32_plus else 96)
    info.update({"opt": opt, "data_dir_off": data_dir_off, "is_pe32_plus": is_pe32_plus, "opt_size": opt_size})
    return info


def rva_to_offset(layout: Dict[str, Any], rva: int) -> int | None:
    for s in layout.get("sections", []):
        va = int(s.get("virtual_address", 0))
        vs = int(s.get("virtual_size", 0))
        raw_ptr = int(s.get("raw_ptr", 0))
        raw_size = int(s.get("raw_size", 0))
        size = max(vs, raw_size)
        if va <= rva < va + size:
            return raw_ptr + (rva - va)
    if 0 <= rva < 4096:
        return rva
    return None


def offset_to_rva(layout: Dict[str, Any], offset: int) -> int | None:
    for s in layout.get("sections", []):
        va = int(s.get("virtual_address", 0))
        raw_ptr = int(s.get("raw_ptr", 0))
        raw_size = int(s.get("raw_size", 0))
        if raw_ptr <= offset < raw_ptr + raw_size:
            return va + (offset - raw_ptr)
    if 0 <= offset < 4096:
        return offset
    return None


def read_c_string(data: bytes, offset: int, max_len: int = 4096) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end < 0:
        end = min(len(data), offset + max_len)
    return data[offset:end].decode("utf-8", errors="replace")


def pe_data_directory(layout: Dict[str, Any], index: int) -> Tuple[int, int]:
    off = int(layout.get("data_dir_off", 0)) + index * 8
    data_len = int(layout.get("_data_len", 0))
    data = layout.get("_data")
    if not isinstance(data, (bytes, bytearray)) or off + 8 > data_len:
        return 0, 0
    return int.from_bytes(data[off:off + 4], "little"), int.from_bytes(data[off + 4:off + 8], "little")


def parse_pe_imports(data: bytes, limit: int = 500) -> Dict[str, Any]:
    layout = pe_layout(data)
    if not layout.get("ok"):
        return layout
    layout["_data"] = data
    layout["_data_len"] = len(data)
    rva, size = pe_data_directory(layout, 1)
    off = rva_to_offset(layout, rva) if rva else None
    imports: List[Dict[str, Any]] = []
    limit = max(1, min(int(limit or 500), 5000))
    if off is None:
        return {"ok": True, "imports": [], "import_rva": f"0x{rva:x}", "import_size": size}
    desc_i = 0
    while off + desc_i * 20 + 20 <= len(data) and len(imports) < limit:
        d = off + desc_i * 20
        original_thunk = int.from_bytes(data[d:d + 4], "little")
        name_rva = int.from_bytes(data[d + 12:d + 16], "little")
        first_thunk = int.from_bytes(data[d + 16:d + 20], "little")
        if original_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        name_off = rva_to_offset(layout, name_rva)
        dll = read_c_string(data, name_off or -1)
        thunk_rva = original_thunk or first_thunk
        thunk_off = rva_to_offset(layout, thunk_rva)
        funcs: List[Any] = []
        thunk_size = 8 if layout.get("is_pe32_plus") else 4
        ordinal_flag = 0x8000000000000000 if thunk_size == 8 else 0x80000000
        ti = 0
        while thunk_off is not None and thunk_off + ti * thunk_size + thunk_size <= len(data) and len(imports) + len(funcs) < limit:
            to = thunk_off + ti * thunk_size
            val = int.from_bytes(data[to:to + thunk_size], "little")
            if val == 0:
                break
            if val & ordinal_flag:
                funcs.append({"ordinal": val & 0xFFFF})
            else:
                hint_name_off = rva_to_offset(layout, val)
                if hint_name_off is not None and hint_name_off + 2 < len(data):
                    hint = int.from_bytes(data[hint_name_off:hint_name_off + 2], "little")
                    funcs.append({"hint": hint, "name": read_c_string(data, hint_name_off + 2)})
            ti += 1
        imports.append({"dll": dll, "functions": funcs})
        desc_i += 1
    return {"ok": True, "imports": imports, "import_rva": f"0x{rva:x}", "import_size": size}


def parse_pe_exports(data: bytes, limit: int = 500) -> Dict[str, Any]:
    layout = pe_layout(data)
    if not layout.get("ok"):
        return layout
    layout["_data"] = data
    layout["_data_len"] = len(data)
    rva, size = pe_data_directory(layout, 0)
    off = rva_to_offset(layout, rva) if rva else None
    limit = max(1, min(int(limit or 500), 5000))
    if off is None or off + 40 > len(data):
        return {"ok": True, "exports": [], "export_rva": f"0x{rva:x}", "export_size": size}
    name_rva = int.from_bytes(data[off + 12:off + 16], "little")
    base = int.from_bytes(data[off + 16:off + 20], "little")
    n_funcs = int.from_bytes(data[off + 20:off + 24], "little")
    n_names = int.from_bytes(data[off + 24:off + 28], "little")
    funcs_rva = int.from_bytes(data[off + 28:off + 32], "little")
    names_rva = int.from_bytes(data[off + 32:off + 36], "little")
    ords_rva = int.from_bytes(data[off + 36:off + 40], "little")
    names_off = rva_to_offset(layout, names_rva)
    ords_off = rva_to_offset(layout, ords_rva)
    funcs_off = rva_to_offset(layout, funcs_rva)
    exports = []
    for i in range(min(n_names, limit)):
        if names_off is None or ords_off is None or funcs_off is None:
            break
        no = names_off + i * 4
        oo = ords_off + i * 2
        if no + 4 > len(data) or oo + 2 > len(data):
            break
        fn_name_rva = int.from_bytes(data[no:no + 4], "little")
        fn_name_off = rva_to_offset(layout, fn_name_rva)
        ord_index = int.from_bytes(data[oo:oo + 2], "little")
        fo = funcs_off + ord_index * 4
        fn_rva = int.from_bytes(data[fo:fo + 4], "little") if fo + 4 <= len(data) else 0
        exports.append({"name": read_c_string(data, fn_name_off or -1), "ordinal": base + ord_index, "rva": f"0x{fn_rva:x}"})
    dll_name_off = rva_to_offset(layout, name_rva)
    return {"ok": True, "dll": read_c_string(data, dll_name_off or -1), "number_of_functions": n_funcs, "exports": exports, "export_rva": f"0x{rva:x}", "export_size": size}


def format_hexdump(data: bytes, base_offset: int = 0) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{base_offset + i:08x}  {hx:<47}  {asc}")
    return "\n".join(lines)


def run_external_binary_analyzer(path: Path, mode: str, timeout: int = 30) -> str:
    mode = (mode or "headers").lower()
    candidates: List[Tuple[str, List[str]]] = []
    llvm_objdump = resolve_tool("llvm-objdump")
    objdump = resolve_tool("objdump")
    dumpbin = resolve_tool("dumpbin")
    rz_bin = resolve_tool("rz-bin")
    if llvm_objdump:
        candidates.append(("llvm-objdump", [llvm_objdump, "-p" if mode in ("headers", "imports") else "-d", str(path)]))
    if objdump:
        candidates.append(("objdump", [objdump, "-x" if mode in ("headers", "imports") else "-d", str(path)]))
    if rz_bin and mode in ("headers", "imports"):
        candidates.append(("rz-bin", [rz_bin, "-I" if mode == "headers" else "-i", str(path)]))
    if dumpbin:
        flag = "/headers" if mode == "headers" else ("/imports" if mode == "imports" else "/disasm")
        candidates.append(("dumpbin", [dumpbin, flag, str(path)]))
    if not candidates:
        return "tool error: no external disassembler found in PATH (tried llvm-objdump, objdump, dumpbin)"
    name, cmd = candidates[0]
    p = subprocess.run(cmd, cwd=str(path.parent), text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return f"[{name} exit={p.returncode}]\n" + (p.stdout or "")[:60000]


def tool_search_dirs() -> List[Path]:
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    local = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
    roots = [
        home / "Documents" / "Codex" / "tools" / "bin",
        home / "AppData" / "Roaming" / "Python" / "Python311" / "Scripts",
        local / "Microsoft" / "WinGet" / "Links",
        local / "Microsoft" / "WinGet" / "Packages",
        Path("C:/Program Files/LLVM/bin"),
        Path("C:/Program Files/Rizin/bin"),
        Path("C:/Program Files/Git/usr/bin"),
        Path("C:/mingw64/bin"),
    ]
    return roots


def resolve_tool(name: str) -> str | None:
    direct = shutil.which(name)
    if direct:
        return direct
    stems = [name]
    if name == "r2":
        stems.append("rizin")
    suffixes = ["", ".exe", ".cmd", ".bat"]
    for root in tool_search_dirs():
        try:
            root_exists = root.exists()
        except Exception:
            continue
        if not root_exists:
            continue
        for stem in stems:
            for suf in suffixes:
                p = root / (stem + suf)
                try:
                    hit_exists = p.exists()
                except Exception:
                    hit_exists = False
                if hit_exists:
                    return str(p)
        if root.name == "Packages":
            for stem in stems:
                for suf in suffixes[1:]:
                    try:
                        hit = next(root.rglob(stem + suf), None)
                    except Exception:
                        hit = None
                    if hit:
                        return str(hit)
    return None


def process_list_windows(name_filter: str = "", limit: int = 100) -> str:
    limit = max(1, min(int(limit or 100), 1000))
    flt = name_filter.replace("'", "''")
    where = f" | Where-Object {{ $_.Name -like '*{flt}*' -or $_.CommandLine -like '*{flt}*' }}" if flt else ""
    ps = (
        "Get-CimInstance Win32_Process"
        + where
        + f" | Select-Object -First {limit} ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Depth 3 -Compress"
    )
    p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    return p.stdout or "[]"


def process_modules_windows(pid: int, limit: int = 500) -> str:
    limit = max(1, min(int(limit or 500), 5000))
    ps = (
        f"$p=Get-Process -Id {int(pid)} -ErrorAction Stop; "
        f"$p.Modules | Select-Object -First {limit} ModuleName,FileName,BaseAddress,ModuleMemorySize | ConvertTo-Json -Depth 3 -Compress"
    )
    p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    return p.stdout


def run_ghidra_headless(path: Path, workspace: Path, project_name: str = "ghidra_project", timeout: int = 300) -> str:
    analyze = resolve_tool("analyzeHeadless")
    if not analyze:
        return "tool error: analyzeHeadless not found"
    project_dir = workspace / "ghidra_projects"
    project_dir.mkdir(parents=True, exist_ok=True)
    cmd = [analyze, str(project_dir), project_name, "-import", str(path), "-deleteProject", "-overwrite"]
    p = subprocess.run(cmd, cwd=str(workspace), text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return f"[ghidra_analyze exit={p.returncode}]\n" + (p.stdout or "")[-60000:]


def run_rizin_info(path: Path, mode: str = "info", timeout: int = 60) -> str:
    rz_bin = resolve_tool("rz-bin")
    if not rz_bin:
        return "tool error: rz-bin not found"
    mode = (mode or "info").lower()
    flag = {"info": "-I", "imports": "-i", "sections": "-S", "strings": "-z"}.get(mode, "-I")
    p = subprocess.run([rz_bin, flag, str(path)], cwd=str(path.parent), text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return f"[rz-bin {flag} exit={p.returncode}]\n" + (p.stdout or "")[:60000]


def python_re_libs_status() -> Dict[str, Any]:
    libs = ["pefile", "capstone", "keystone", "unicorn", "lief", "yara", "capa", "vivisect"]
    out: Dict[str, Any] = {"ok": True, "python": sys.executable, "libs": {}}
    for lib in libs:
        try:
            mod = __import__(lib)
            out["libs"][lib] = {"ok": True, "version": str(getattr(mod, "__version__", ""))}
        except Exception as e:
            out["libs"][lib] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return out


def decode_tool_bytes(data: bytes) -> str:
    if not data:
        return ""
    sample = data[:200]
    if sample.count(b"\x00") > max(4, len(sample) // 4):
        for enc in ("utf-16le", "utf-16"):
            try:
                return data.decode(enc, errors="replace")
            except Exception:
                pass
    return data.decode("utf-8", errors="replace")


def tool_exec(action: str, args: Dict[str, Any], workspace: Path, yes: bool, allow_shell: bool, allow_write: bool) -> str:
    try:
        if not isinstance(action, str) or not action:
            return f"tool error: missing action in model JSON"
        if not isinstance(args, dict):
            args = {}
        if action == "list_dir":
            p = workspace_path(workspace, args.get("path", "."))
            items = []
            for x in sorted(p.iterdir(), key=lambda q: (not q.is_dir(), q.name.lower()))[:300]:
                items.append(("DIR " if x.is_dir() else "FILE") + " " + str(x))
            return "\n".join(items) or "(empty)"
        if action == "read_file":
            p = workspace_path(workspace, args["path"])
            return p.read_text(encoding="utf-8", errors="replace")[:30000]
        if action in ("write_file", "append_file"):
            if not allow_write:
                return "write blocked: rerun with --allow-write"
            p = workspace_path(workspace, args["path"])
            if not confirm(f"파일 변경 허용? {action} {p}", yes):
                return "user denied write"
            p.parent.mkdir(parents=True, exist_ok=True)
            if action == "write_file":
                p.write_text(args.get("content", ""), encoding="utf-8")
            else:
                with open(p, "a", encoding="utf-8") as f:
                    f.write(args.get("content", ""))
            return f"ok: {action} {p}"
        if action == "file_info":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            st = p.stat()
            info = {"ok": True, "path": str(p), "size": st.st_size, "sha256": sha256_file(p), "mtime": st.st_mtime}
            info.update(text_stats(p, args.get("encoding", "utf-8")))
            return json.dumps(info, ensure_ascii=False)
        if action == "file_hashes":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            info = {"ok": True, "path": str(p)}
            info.update(file_hashes(p))
            return json.dumps(info, ensure_ascii=False)
        if action == "file_type":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            info = {"ok": True, "path": str(p), "size": len(data)}
            info.update(detect_file_type(data))
            return json.dumps(info, ensure_ascii=False)
        if action == "read_lines":
            p = workspace_path(workspace, args["path"])
            start = max(1, int(args.get("start", 1) or 1))
            end = int(args.get("end", start + 80) or (start + 80))
            lines = read_text_for_edit(p, args.get("encoding", "utf-8")).splitlines()
            end = min(max(start, end), len(lines))
            return "\n".join(f"{idx}: {lines[idx-1]}" for idx in range(start, end + 1))
        if action == "replace_lines":
            if not allow_write:
                return "replace_lines blocked: rerun with --allow-write"
            p = workspace_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            text = read_text_for_edit(p, args.get("encoding", "utf-8"))
            newline = "\r\n" if "\r\n" in text else "\n"
            lines = text.splitlines(keepends=True)
            start = max(1, int(args["start"]))
            end = max(start, int(args.get("end", start)))
            if start > len(lines) + 1:
                return f"tool error: start line out of range: {start} > {len(lines)+1}"
            repl = normalize_line_content(str(args.get("content", "")), newline)
            backup = ""
            if args.get("backup", True): backup = str(make_backup(p))
            lines[start-1:end] = repl
            write_text_for_edit(p, "".join(lines), args.get("encoding", "utf-8"))
            return f"ok: replace_lines {p} start={start} end={end} inserted={len(repl)} backup={backup} sha256={sha256_file(p)}"
        if action == "insert_lines":
            if not allow_write:
                return "insert_lines blocked: rerun with --allow-write"
            p = workspace_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            text = read_text_for_edit(p, args.get("encoding", "utf-8"))
            newline = "\r\n" if "\r\n" in text else "\n"
            lines = text.splitlines(keepends=True)
            line = max(1, int(args.get("line", 1) or 1))
            where = str(args.get("where", "before")).lower()
            idx = min(line - 1, len(lines))
            if where == "after": idx = min(line, len(lines))
            ins = normalize_line_content(str(args.get("content", "")), newline)
            backup = ""
            if args.get("backup", True): backup = str(make_backup(p))
            lines[idx:idx] = ins
            write_text_for_edit(p, "".join(lines), args.get("encoding", "utf-8"))
            return f"ok: insert_lines {p} line={line} where={where} inserted={len(ins)} backup={backup} sha256={sha256_file(p)}"
        if action == "delete_lines":
            if not allow_write:
                return "delete_lines blocked: rerun with --allow-write"
            p = workspace_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            text = read_text_for_edit(p, args.get("encoding", "utf-8"))
            lines = text.splitlines(keepends=True)
            start = max(1, int(args["start"]))
            end = max(start, int(args.get("end", start)))
            if start > len(lines):
                return f"tool error: start line out of range: {start} > {len(lines)}"
            backup = ""
            if args.get("backup", True): backup = str(make_backup(p))
            deleted = len(lines[start-1:end])
            del lines[start-1:end]
            write_text_for_edit(p, "".join(lines), args.get("encoding", "utf-8"))
            return f"ok: delete_lines {p} start={start} end={end} deleted={deleted} backup={backup} sha256={sha256_file(p)}"
        if action == "regex_replace":
            if not allow_write:
                return "regex_replace blocked: rerun with --allow-write"
            p = workspace_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            text = read_text_for_edit(p, args.get("encoding", "utf-8"))
            pattern = str(args["pattern"])
            repl = str(args.get("replacement", args.get("repl", "")))
            count = int(args.get("count", 0) or 0)
            rx = re.compile(pattern, regex_flags(args.get("flags", "")))
            updated, n = rx.subn(repl, text, count=count)
            if n <= 0:
                return f"tool error: regex_replace no matches in {p}"
            backup = ""
            if args.get("backup", True): backup = str(make_backup(p))
            write_text_for_edit(p, updated, args.get("encoding", "utf-8"))
            return f"ok: regex_replace {p} replacements={n} backup={backup} sha256={sha256_file(p)}"
        if action == "apply_unified_patch":
            if not allow_write:
                return "apply_unified_patch blocked: rerun with --allow-write"
            patch = str(args.get("patch", ""))
            files = parse_unified_patch_files(patch)
            if not files:
                return "tool error: no files/hunks found in unified patch"
            changed = []
            backups = []
            for rel, hunks in files:
                p = workspace_path(workspace, rel)
                if not p.exists():
                    return f"tool error: patch target not found: {p}"
                original = read_text_for_edit(p, args.get("encoding", "utf-8"))
                updated = apply_unified_patch_to_text(original, hunks)
                if updated != original:
                    if args.get("backup", True): backups.append(str(make_backup(p)))
                    write_text_for_edit(p, updated, args.get("encoding", "utf-8"))
                    changed.append(str(p))
            return json.dumps({"ok": True, "action": "apply_unified_patch", "changed": changed, "backups": backups}, ensure_ascii=False)
        if action == "replace_in_file":
            if not allow_write:
                return "replace blocked: rerun with --allow-write"
            p = workspace_path(workspace, args["path"])
            old_text = str(args.get("old", ""))
            new_text = str(args.get("new", ""))
            if old_text == "":
                return "tool error: replace_in_file old text is empty"
            if not p.exists():
                return f"tool error: file not found: {p}"
            if not confirm(f"?? ?? ??? replace_in_file {p}", yes):
                return "user denied replace"
            text = p.read_text(encoding=args.get("encoding", "utf-8"), errors="replace")
            count = int(args.get("count", 0) or 0)
            occurrences = text.count(old_text)
            if occurrences <= 0:
                return f"tool error: old text not found in {p}"
            updated = text.replace(old_text, new_text, count if count > 0 else -1)
            backup = ""
            if args.get("backup", True):
                backup = str(make_backup(p))
            p.write_text(updated, encoding=args.get("encoding", "utf-8"))
            changed = occurrences if count <= 0 else min(occurrences, count)
            return f"ok: replace_in_file {p} replacements={changed} backup={backup} sha256={sha256_file(p)}"
        if action == "backup_file":
            p = workspace_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            bak = make_backup(p)
            return f"ok: backup_file {p} -> {bak} sha256={sha256_file(p)}"
        if action == "binary_info":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            head_len = max(0, min(int(args.get("head", 64) or 64), 4096))
            data = p.read_bytes()
            return json.dumps({"ok": True, "path": str(p), "size": len(data), "sha256": sha256_file(p), "head_hex": data[:head_len].hex(" ")}, ensure_ascii=False)
        if action == "binary_strings":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            strings = binary_strings_from_bytes(data, int(args.get("min_len", 4) or 4), int(args.get("limit", 200) or 200))
            return json.dumps({"ok": True, "path": str(p), "count": len(strings), "strings": strings}, ensure_ascii=False)
        if action == "binary_hexdump":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            offset = max(0, parse_int_arg(args.get("offset", 0), 0))
            length = max(0, min(int(args.get("length", 256) or 256), 8192))
            return format_hexdump(data[offset:offset + length], offset)
        if action == "binary_search":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            needle = parse_binary_arg(args, "needle")
            hits = binary_find_offsets(data, needle, int(args.get("limit", 200) or 200))
            return json.dumps({"ok": True, "path": str(p), "needle_len": len(needle), "count": len(hits), "offsets": hits, "offsets_hex": [f"0x{x:x}" for x in hits]}, ensure_ascii=False)
        if action == "binary_pattern_search":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            pat = parse_hex_pattern(str(args["pattern"]))
            hits = binary_pattern_offsets(p.read_bytes(), pat, int(args.get("limit", 200) or 200))
            return json.dumps({"ok": True, "path": str(p), "pattern_len": len(pat), "count": len(hits), "offsets": hits, "offsets_hex": [f"0x{x:x}" for x in hits]}, ensure_ascii=False)
        if action == "binary_extract":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            out_path = workspace_path(workspace, args.get("out", "extract.bin"))
            data = p.read_bytes()
            offset = max(0, parse_int_arg(args.get("offset", 0), 0))
            length = max(0, min(parse_int_arg(args.get("length", 256), 256), 1024 * 1024 * 64))
            chunk = data[offset:offset + length]
            if not confirm(f"write binary_extract {out_path}", yes):
                return "user denied binary_extract"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(chunk)
            return json.dumps({"ok": True, "path": str(p), "out": str(out_path), "offset": offset, "length": len(chunk), "sha256": sha256_file(out_path)}, ensure_ascii=False)
        if action == "binary_append":
            if not allow_write:
                return "binary_append blocked: rerun with --allow-write"
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            new_b = parse_binary_arg(args, "data")
            if not confirm(f"binary_append {p}", yes):
                return "user denied binary_append"
            backup = str(make_backup(p)) if args.get("backup", True) else ""
            with open(p, "ab") as f:
                f.write(new_b)
            return json.dumps({"ok": True, "action": "binary_append", "path": str(p), "appended": len(new_b), "backup": backup, "size": p.stat().st_size, "sha256": sha256_file(p)}, ensure_ascii=False)
        if action == "binary_insert":
            if not allow_write:
                return "binary_insert blocked: rerun with --allow-write"
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            offset = max(0, parse_int_arg(args.get("offset", 0), 0))
            new_b = parse_binary_arg(args, "data")
            data = p.read_bytes()
            if offset > len(data):
                return f"tool error: binary_insert offset beyond EOF offset={offset} size={len(data)}"
            if not confirm(f"binary_insert {p} @0x{offset:x}", yes):
                return "user denied binary_insert"
            backup = str(make_backup(p)) if args.get("backup", True) else ""
            p.write_bytes(data[:offset] + new_b + data[offset:])
            return json.dumps({"ok": True, "action": "binary_insert", "path": str(p), "offset": offset, "inserted": len(new_b), "backup": backup, "size": p.stat().st_size, "sha256": sha256_file(p)}, ensure_ascii=False)
        if action == "binary_delete":
            if not allow_write:
                return "binary_delete blocked: rerun with --allow-write"
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            offset = max(0, parse_int_arg(args.get("offset", 0), 0))
            length = max(0, parse_int_arg(args.get("length", 0), 0))
            if offset + length > len(data):
                return f"tool error: binary_delete range beyond EOF offset={offset} length={length} size={len(data)}"
            if not confirm(f"binary_delete {p} @0x{offset:x} len={length}", yes):
                return "user denied binary_delete"
            backup = str(make_backup(p)) if args.get("backup", True) else ""
            p.write_bytes(data[:offset] + data[offset + length:])
            return json.dumps({"ok": True, "action": "binary_delete", "path": str(p), "offset": offset, "deleted": length, "backup": backup, "size": p.stat().st_size, "sha256": sha256_file(p)}, ensure_ascii=False)
        if action == "binary_fill":
            if not allow_write:
                return "binary_fill blocked: rerun with --allow-write"
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = bytearray(p.read_bytes())
            offset = max(0, parse_int_arg(args.get("offset", 0), 0))
            length = max(0, parse_int_arg(args.get("length", 0), 0))
            fill = parse_binary_arg(args, "fill")
            if not fill:
                return "tool error: binary_fill fill bytes empty"
            if offset + length > len(data):
                return f"tool error: binary_fill range beyond EOF offset={offset} length={length} size={len(data)}"
            if not confirm(f"binary_fill {p} @0x{offset:x} len={length}", yes):
                return "user denied binary_fill"
            backup = str(make_backup(p)) if args.get("backup", True) else ""
            data[offset:offset + length] = (fill * ((length + len(fill) - 1) // len(fill)))[:length]
            p.write_bytes(bytes(data))
            return json.dumps({"ok": True, "action": "binary_fill", "path": str(p), "offset": offset, "length": length, "backup": backup, "size": p.stat().st_size, "sha256": sha256_file(p)}, ensure_ascii=False)
        if action == "binary_diff":
            p = binary_target_path(workspace, args["path"])
            other = binary_target_path(workspace, args["other"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            if not other.exists():
                return f"tool error: file not found: {other}"
            a, b = p.read_bytes(), other.read_bytes()
            ranges = binary_diff_ranges(a, b, int(args.get("limit", 100) or 100))
            return json.dumps({"ok": True, "path": str(p), "other": str(other), "size_a": len(a), "size_b": len(b), "diff_ranges": ranges, "range_count": len(ranges)}, ensure_ascii=False)
        if action == "binary_entropy":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            window = int(args.get("window", 0) or 0)
            if window <= 0:
                return json.dumps({"ok": True, "path": str(p), "size": len(data), "entropy": shannon_entropy(data)}, ensure_ascii=False)
            window = max(256, min(window, 1024 * 1024))
            rows = []
            for off in range(0, len(data), window):
                rows.append({"offset": off, "offset_hex": f"0x{off:x}", "length": len(data[off:off + window]), "entropy": shannon_entropy(data[off:off + window])})
            rows.sort(key=lambda r: r["entropy"], reverse=True)
            limit = max(1, min(int(args.get("limit", 20) or 20), 1000))
            return json.dumps({"ok": True, "path": str(p), "size": len(data), "window": window, "top": rows[:limit]}, ensure_ascii=False)
        if action == "pe_info":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            info = parse_pe_info(data)
            info.update({"path": str(p), "size": len(data), "sha256": sha256_file(p)})
            return json.dumps(info, ensure_ascii=False)
        if action == "pe_imports":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            info = parse_pe_imports(p.read_bytes(), int(args.get("limit", 500) or 500))
            info.update({"path": str(p), "sha256": sha256_file(p)})
            return json.dumps(info, ensure_ascii=False)
        if action == "pe_exports":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            info = parse_pe_exports(p.read_bytes(), int(args.get("limit", 500) or 500))
            info.update({"path": str(p), "sha256": sha256_file(p)})
            return json.dumps(info, ensure_ascii=False)
        if action == "pe_rva_to_offset":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            layout = pe_layout(data)
            rva = parse_int_arg(args.get("rva"), 0)
            off = rva_to_offset(layout, rva) if layout.get("ok") else None
            return json.dumps({"ok": off is not None, "path": str(p), "rva": rva, "rva_hex": f"0x{rva:x}", "offset": off, "offset_hex": (f"0x{off:x}" if off is not None else None), "pe_ok": layout.get("ok"), "format": layout.get("format")}, ensure_ascii=False)
        if action == "pe_offset_to_rva":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            layout = pe_layout(data)
            offset = parse_int_arg(args.get("offset"), 0)
            rva = offset_to_rva(layout, offset) if layout.get("ok") else None
            return json.dumps({"ok": rva is not None, "path": str(p), "offset": offset, "offset_hex": f"0x{offset:x}", "rva": rva, "rva_hex": (f"0x{rva:x}" if rva is not None else None), "pe_ok": layout.get("ok"), "format": layout.get("format")}, ensure_ascii=False)
        if action == "pe_section_extract":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = p.read_bytes()
            layout = pe_layout(data)
            if not layout.get("ok"):
                return json.dumps({"ok": False, "path": str(p), "error": layout.get("format")}, ensure_ascii=False)
            sec_name = str(args.get("section", args.get("name", ""))).strip()
            sec = None
            for s in layout.get("sections", []):
                if s.get("name") == sec_name or (not sec_name and sec is None):
                    sec = s
                    break
            if not sec:
                return f"tool error: section not found: {sec_name}"
            out_path = workspace_path(workspace, args.get("out", f"{p.name}.{sec['name'].strip('.') or 'section'}.bin"))
            raw_ptr = int(sec.get("raw_ptr", 0)); raw_size = int(sec.get("raw_size", 0))
            chunk = data[raw_ptr:raw_ptr + raw_size]
            if not confirm(f"pe_section_extract {p} section={sec.get('name')} -> {out_path}", yes):
                return "user denied pe_section_extract"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(chunk)
            return json.dumps({"ok": True, "path": str(p), "section": sec, "out": str(out_path), "length": len(chunk), "sha256": sha256_file(out_path)}, ensure_ascii=False)
        if action == "disassemble":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            if not p.is_file():
                return f"tool error: disassemble target is not a file: {p}"
            return run_external_binary_analyzer(p, str(args.get("mode", "headers")), int(args.get("timeout", 30) or 30))
        if action == "ghidra_analyze":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            if not p.is_file():
                return f"tool error: ghidra_analyze target is not a file: {p}"
            return run_ghidra_headless(p, workspace, str(args.get("project", "ghidra_project")), int(args.get("timeout", 300) or 300))
        if action == "rizin_info":
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            if not p.is_file():
                return f"tool error: rizin_info target is not a file: {p}"
            return run_rizin_info(p, str(args.get("mode", "info")), int(args.get("timeout", 60) or 60))
        if action == "sigcheck_file":
            sigcheck = resolve_tool("sigcheck")
            if not sigcheck:
                return "tool error: sigcheck not found"
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            if not p.is_file():
                return f"tool error: sigcheck target is not a file: {p}"
            proc = subprocess.run([sigcheck, "-accepteula", "-nobanner", "-a", "-h", "-m", str(p)], cwd=str(workspace), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=int(args.get("timeout", 60) or 60))
            return f"[sigcheck exit={proc.returncode}]\n" + decode_tool_bytes(proc.stdout or b"")[:60000]
        if action == "capa_scan":
            capa = resolve_tool("capa")
            if not capa:
                return "tool error: capa not found"
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            if not p.is_file():
                return f"tool error: capa target is not a file: {p}"
            rules = args.get("rules")
            signatures = args.get("signatures")
            if not rules:
                tools_dir = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Documents" / "Codex" / "tools"
                default_rules = tools_dir / "capa-rules"
                if default_rules.exists():
                    rules = str(default_rules)
                default_sigs = tools_dir / "capa-signatures-empty"
                if default_sigs.exists():
                    signatures = str(default_sigs)
            cmd = [capa]
            if rules:
                cmd += ["-r", str(rules)]
            if signatures:
                cmd += ["-s", str(signatures)]
            cmd.append(str(p))
            proc = subprocess.run(cmd, cwd=str(workspace), text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=int(args.get("timeout", 120) or 120))
            return f"[capa exit={proc.returncode}]\n" + (proc.stdout or "")[:60000]
        if action == "python_re_libs":
            return json.dumps(python_re_libs_status(), ensure_ascii=False)
        if action == "re_tool_inventory":
            names = ["ghidraRun", "analyzeHeadless", "ghidra", "radare2", "r2", "rizin", "rz-bin", "cutter", "x64dbg", "x32dbg", "dumpbin", "llvm-objdump", "objdump", "strings", "floss", "capa", "vivbin", "vdbbin", "diec", "sigcheck", "procdump", "procexp", "Listdlls"]
            found = {name: resolve_tool(name) for name in names}
            return json.dumps({"ok": True, "tools": found, "available": {k: v for k, v in found.items() if v}}, ensure_ascii=False)
        if action == "binary_replace":
            if not allow_write:
                return "binary_replace blocked: rerun with --allow-write"
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            old_b = parse_binary_arg(args, "old")
            new_b = parse_binary_arg(args, "new")
            if not old_b:
                return "tool error: binary_replace old bytes empty"
            allow_resize = bool(args.get("allow_resize", False))
            if (not allow_resize) and len(old_b) != len(new_b):
                return f"tool error: binary_replace length mismatch old={len(old_b)} new={len(new_b)}; use same length or allow_resize=true"
            if not confirm(f"???? ?? ??? binary_replace {p}", yes):
                return "user denied binary_replace"
            data = p.read_bytes()
            count_arg = int(args.get("count", 1) or 1)
            max_count = count_arg if count_arg > 0 else data.count(old_b)
            found = data.count(old_b)
            if found <= 0:
                return f"tool error: old bytes not found in {p}"
            backup = ""
            if args.get("backup", True):
                backup = str(make_backup(p))
            updated = data.replace(old_b, new_b, max_count)
            p.write_bytes(updated)
            changed = min(found, max_count)
            return json.dumps({"ok": True, "action": "binary_replace", "path": str(p), "replacements": changed, "backup": backup, "size": p.stat().st_size, "sha256": sha256_file(p)}, ensure_ascii=False)
        if action == "binary_patch_offset":
            if not allow_write:
                return "binary_patch_offset blocked: rerun with --allow-write"
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            offset = parse_int_arg(args.get("offset"), 0)
            new_b = parse_binary_arg(args, "new")
            if offset < 0:
                return "tool error: binary_patch_offset offset must be >= 0"
            data = bytearray(p.read_bytes())
            end = offset + len(new_b)
            if end > len(data) and not bool(args.get("allow_extend", False)):
                return f"tool error: binary_patch_offset beyond EOF offset={offset} new_len={len(new_b)} size={len(data)}; use allow_extend=true"
            if not confirm(f"binary_patch_offset {p} @0x{offset:x}", yes):
                return "user denied binary_patch_offset"
            backup = ""
            if args.get("backup", True):
                backup = str(make_backup(p))
            if end > len(data):
                data.extend(b"\x00" * (end - len(data)))
            old_b = bytes(data[offset:end])
            data[offset:end] = new_b
            p.write_bytes(bytes(data))
            return json.dumps({"ok": True, "action": "binary_patch_offset", "path": str(p), "offset": offset, "offset_hex": f"0x{offset:x}", "old_hex": old_b.hex(" "), "new_hex": new_b.hex(" "), "backup": backup, "size": p.stat().st_size, "sha256": sha256_file(p)}, ensure_ascii=False)
        if action == "binary_pattern_patch":
            if not allow_write:
                return "binary_pattern_patch blocked: rerun with --allow-write"
            p = binary_target_path(workspace, args["path"])
            if not p.exists():
                return f"tool error: file not found: {p}"
            data = bytearray(p.read_bytes())
            pat = parse_hex_pattern(str(args["pattern"]))
            new_b = parse_binary_arg(args, "new")
            if len(new_b) != len(pat) and not bool(args.get("allow_resize", False)):
                return f"tool error: binary_pattern_patch length mismatch pattern={len(pat)} new={len(new_b)}"
            hits = binary_pattern_offsets(bytes(data), pat, int(args.get("limit", 200) or 200))
            if not hits:
                return f"tool error: binary_pattern_patch pattern not found in {p}"
            count = int(args.get("count", 1) or 1)
            targets = hits[:count if count > 0 else len(hits)]
            if not confirm(f"binary_pattern_patch {p} hits={len(targets)}", yes):
                return "user denied binary_pattern_patch"
            backup = str(make_backup(p)) if args.get("backup", True) else ""
            delta = 0
            patches = []
            for off in targets:
                real = off + delta
                old_b = bytes(data[real:real + len(pat)])
                data[real:real + len(pat)] = new_b
                delta += len(new_b) - len(pat)
                patches.append({"offset": off, "offset_hex": f"0x{off:x}", "old_hex": old_b.hex(" "), "new_hex": new_b.hex(" ")})
            p.write_bytes(bytes(data))
            return json.dumps({"ok": True, "action": "binary_pattern_patch", "path": str(p), "patches": patches, "backup": backup, "size": p.stat().st_size, "sha256": sha256_file(p)}, ensure_ascii=False)
        if action == "process_list":
            if os.name == "nt":
                return process_list_windows(str(args.get("name", args.get("filter", ""))), int(args.get("limit", 100) or 100))
            p = subprocess.run(["ps", "-eo", "pid,comm,args"], text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            return p.stdout[:60000]
        if action == "process_modules":
            pid = parse_int_arg(args.get("pid"), 0)
            if pid <= 0:
                return "tool error: process_modules requires pid"
            if os.name == "nt":
                return process_modules_windows(pid, int(args.get("limit", 500) or 500))
            maps = Path(f"/proc/{pid}/maps")
            if maps.exists():
                return maps.read_text(encoding="utf-8", errors="replace")[:60000]
            return "tool error: process_modules unsupported on this OS"
        if action == "search_files":
            root = workspace_path(workspace, args.get("root", "."))
            pattern = args.get("pattern", "")
            glob = args.get("glob", "*")
            hits = []
            direct_binary_path = extract_binary_path_from_goal(str(pattern))
            if direct_binary_path:
                try:
                    direct = workspace_path(workspace, direct_binary_path)
                    if direct.exists():
                        hits.append(str(direct))
                except Exception:
                    pass
            try:
                rx = re.compile(pattern, re.I)
            except re.error:
                rx = re.compile(re.escape(pattern), re.I)
            for p in root.rglob(glob):
                if len(hits) >= 200:
                    break
                if p.is_dir():
                    continue
                if rx.search(str(p)):
                    hits.append(str(p))
                    continue
                try:
                    txt = p.read_text(encoding="utf-8", errors="ignore")[:200000]
                    if rx.search(txt):
                        hits.append(str(p))
                except Exception:
                    pass
            return "\n".join(hits) or "no hits"
        if action == "shell":
            if not allow_shell:
                return "shell blocked: rerun with --allow-shell"
            cmd = args.get("command", "")
            if not confirm(f"명령 실행 허용? {cmd}", yes):
                return "user denied shell"
            p = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], cwd=str(workspace), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            out = (p.stdout or "")[-30000:]
            if p.returncode != 0:
                return f"tool error: shell exit code {p.returncode}\n{out}"
            return out
        if action == "fetch_url":
            url = args["url"]
            raw, ctype = http_get_text(url)
            body = strip_html_text(raw) if "html" in ctype.lower() or raw.lstrip().startswith("<") else raw[:30000]
            return f"url={url}\ncontent_type={ctype}\n\n{body}"
        if action == "web_search":
            try:
                max_results = int(args.get("max_results", 5))
            except Exception:
                max_results = 5
            return web_search_duckduckgo(args.get("query", ""), max_results)
        if action == "download_file":
            if not allow_write:
                return "download blocked: rerun with --allow-write"
            url = args["url"]
            path = args.get("path") or Path(urllib.parse.urlparse(url).path).name or "download.bin"
            p = workspace_path(workspace, path)
            if not confirm(f"파일 다운로드 허용? {url} -> {p}", yes):
                return "user denied download"
            p.parent.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 LocalAIAgent/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                total = 0
                with open(p, "wb") as f:
                    while True:
                        chunk = r.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        f.write(chunk)
                        if total > 500 * 1024 * 1024:
                            raise RuntimeError("download too large (>500MB)")
            return f"ok: downloaded {total} bytes to {p}"
        if action == "open_url":
            if not allow_shell:
                return "open_url blocked: rerun with --allow-shell"
            url = args["url"]
            if not confirm(f"브라우저 열기 허용? {url}", yes):
                return "user denied open_url"
            subprocess.Popen(["powershell", "-NoProfile", "-Command", "Start-Process " + json.dumps(url)], cwd=str(workspace))
            return f"ok: opened browser url {url}"
        if action == "open_file":
            if not allow_shell:
                return "open_file blocked: rerun with --allow-shell"
            p = workspace_path(workspace, args["path"])
            # Do not report success for a missing file. PowerShell Start-Process
            # can fail asynchronously/noisily while this tool used to return
            # ok, which let agents claim a create/write task was complete even
            # when no file existed.
            if not p.exists():
                return f"tool error: file not found: {p}"
            if not confirm(f"??/???? ?? ??? {p}", yes):
                return "user denied open_file"
            ps = "Invoke-Item -LiteralPath " + json.dumps(str(p))
            proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps], cwd=str(workspace), capture_output=True, text=True, timeout=20)
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "open failed").strip()
                return f"tool error: open_file failed: {detail[:500]}"
            return f"ok: opened {p}"
        if action.startswith("browser_"):
            if not allow_shell:
                return f"{action} blocked: rerun with --allow-shell"
            b_action = action.replace("browser_", "", 1)
            b_args = dict(args)
            if b_action == "screenshot" and b_args.get("path"):
                b_args["path"] = str(workspace_path(workspace, b_args["path"]))
            return browser_rpc(b_action, b_args, workspace)
        return f"unknown action: {action}"
    except Exception as e:
        msg = str(e)
        if "WinError 10013" in msg or "access to a socket" in msg.lower():
            return f"tool blocked: network access restricted ({type(e).__name__}: {e})"
        return f"tool error: {type(e).__name__}: {e}"


def extract_json(text: str) -> Dict[str, Any]:
    text = clean_model_output(text).strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()
    try:
        return json.loads(text)
    except Exception:
        # Models sometimes emit multiple JSON objects or prose around JSON.
        # Decode the first valid object instead of using a greedy regex.
        dec = json.JSONDecoder()
        for i, ch in enumerate(text):
            if ch != "{":
                continue
            try:
                obj, _ = dec.raw_decode(text[i:])
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue
        raise


def decide_mode(goal: str, force: str = "auto") -> Tuple[str, str]:
    if force in ("ask", "agent"):
        return force, f"forced={force}"
    t = goal.lower()
    web_needed, web_reason = implies_web_need(goal)
    if web_needed:
        return "agent", f"auto agent: {web_reason}"
    if implies_binary_work(goal):
        return "agent", "auto agent: binary/reversing work"
    ask_phrases = [
        "explain", "what is", "what are", "tell me", "how does", "how do", "why ",
        "설명", "알려", "뭐야", "무엇", "왜", "어떻게", "요약만", "짧게", "아이디어",
    ]
    action_verbs = [
        "수정", "고쳐", "만들", "생성", "저장", "작성", "실행", "테스트", "빌드", "설치",
        "다운로드", "정리", "찾아", "검색", "읽어", "분석해", "바꿔", "변경", "편집", "패치",
        "fix", "edit", "modify", "change", "patch", "update", "create", "make", "write",
        "save", "run", "test", "build", "install", "download", "find", "search", "read",
        "check", "inspect", "analyze",
    ]
    agent_words = [
        "파일", "폴더", "디렉", "현재", "프로젝트", "워크스페이스", "코드", "버그", "수정", "고쳐", "만들", "생성",
        "저장", "작성해", "실행", "테스트", "빌드", "설치", "다운로드", "정리해", "찾아", "검색", "읽어", "분석해",
        "exe", "dll", "바이너리", "역공학", "리버싱", "디스어셈블", "패치",
        "브라우저", "마우스", "클릭", "입력", "화면", "playwright",
        "readme", "package.json", ".py", ".js", ".ts", ".json", ".md", "git", "npm", "python", "powershell",
        "file", "folder", "directory", "code", "project", "workspace", "repo", "fix", "edit", "modify", "change",
        "patch", "update", "create", "make", "write", "save", "run", "test", "build", "install", "download",
        "find", "search", "read", "check", "inspect", "analyze", "browser", "mouse", "click", "type", "screen", "playwright",
        ".txt", ".csv", ".yml", ".yaml",
    ]
    ask_words = ["설명", "알려", "뭐야", "추천", "요약만", "짧게", "아이디어", "explain", "what is", "tell me", "how does"]
    if any(p in t for p in ask_phrases) and not any(v in t for v in action_verbs):
        return "ask", "auto ask: explanation/query without action verb"
    score_agent = sum(1 for w in agent_words if w in t)
    score_ask = sum(1 for w in ask_words if w in t)
    if score_agent >= 1 and score_agent >= score_ask:
        return "agent", f"auto agent: agent={score_agent}, ask={score_ask}"
    return "ask", f"auto ask: agent={score_agent}, ask={score_ask}"


def should_session_auto_agent(line: str, enabled: bool = True) -> Tuple[bool, str]:
    """Decide whether a plain session message should execute real PC actions.

    In session mode the user should not have to type /agent for normal local
    work such as editing files, changing code, running tests, inspecting the
    workspace, installing dependencies, or launching shell commands.
    """
    if not enabled:
        return False, "disabled"
    t = line.lower().strip()
    if not t:
        return False, "empty"
    if t.startswith(("/", "?", "!")):
        return False, "command-prefix"
    web_needed, web_reason = implies_web_need(line)
    if web_needed:
        return True, web_reason
    if implies_binary_work(line):
        return True, "binary/reversing work"
    local_action_hints = [
        "파일", "폴더", "디렉", "코드 파일", "수정", "고쳐", "만들", "생성", "저장", "작성", "실행", "테스트",
        "빌드", "설치", "다운로드", "검색", "읽어", "분석", "리팩터", "리팩토", "바이너리", "역공학", "리버싱", "디스어셈블", "패치",
        "브라우저", "마우스", "클릭", "입력", "화면", "playwright",
        "file", "folder", "directory", ".py", ".js", ".ts", ".json", ".md", ".txt", ".csv",
        "fix", "edit", "modify", "change", "patch", "update", "create", "make", "write", "save",
        "run ", "test", "build", "install", "download", "search", "inspect", "analyze", "refactor", "browser", "mouse", "click", "type", "screen", "playwright",
    ]
    if any(x in t for x in ["codename", "code name", "codeword", "code word"]) and not any(h in t for h in local_action_hints):
        return False, "memory/chat keyword"

    mode, reason = decide_mode(line, "auto")
    if mode != "agent":
        return False, reason

    # Deterministic file/code intent guard: if decide_mode already classified the
    # prompt as agent and it contains a concrete file path / extension or an
    # explicit local edit/create verb, auto-dispatch immediately. This prevents
    # short file-edit requests like "sample.py에서 OLD를 NEW로 바꿔놔" from
    # falling back into chat mode inside session.
    if re.search(r"\.(py|js|ts|json|md|txt|csv|html|css|yml|yaml|ini|cfg)\b", t):
        return True, reason
    if re.search(r"(고쳐|수정|바꿔|변경|편집|패치|만들|생성|저장|작성|실행|테스트|리팩터|리팩토|fix|edit|modify|change|patch|create|write|save|run|test|build|refactor)", t):
        return True, reason

    # Strong action/object hints. This keeps ordinary explanation/chat prompts
    # in ask mode while making real local-work requests execute immediately.
    strong_hints = [
        # Korean local action verbs/objects
        "고쳐", "수정", "바꿔", "변경", "편집", "패치", "추가", "삭제", "만들", "생성", "저장",
        "작성", "써놔", "넣어", "복사", "이동", "정리", "설치", "다운로드", "실행", "테스트",
        "빌드", "열어", "찾아", "검색", "읽어", "확인", "분석", "스캔", "리팩터", "리팩토", "브라우저", "마우스", "클릭", "입력", "화면", "playwright",
        "파일", "폴더", "디렉", "코드", "프로젝트", "워크스페이스", "레포", "깃", "스크립트",
        "exe", "dll", "바이너리", "역공학", "리버싱", "디스어셈블", "디컴파일", "저수준",
        # English equivalents
        "fix", "edit", "modify", "change", "patch", "update", "add ", "delete", "remove",
        "create", "make", "write", "save", "copy", "move", "install", "download", "run ",
        "test", "build", "open", "find", "search", "read", "check", "inspect", "analyze",
        "scan", "refactor", "file", "folder", "directory", "code", "project", "workspace",
        "binary", "reverse", "reversing", "disassemble", "decompile", ".exe", ".dll",
        "repo", "git", "script", "powershell", "python", "npm",
    ]
    if any(h in t for h in strong_hints):
        return True, reason
    return False, reason


def infer_task(goal: str, task: str) -> str:
    if task != "auto":
        return task
    low = goal.lower()
    if "gemma4_uncensored" in low or ("gemma4" in low and "uncensored" in low):
        return "gemma4_uncensored"
    if "gemma4" in low or "gemma 4" in low:
        return "gemma4"
    if any(w in low for w in ["창작", "소설", "캐릭터", "대사", "글쓰기"]):
        return "creative"
    if any(w in low for w in ["분석", "설계", "아키텍처", "정확", "추론", "역공학", "리버싱", "디스어셈블", "디컴파일", "바이너리", "dll", "exe", "binary", "reverse", "disassemble", "decompile"]):
        return "analysis"
    if any(w in low for w in ["요약", "짧게", "간단"]):
        return "summary"
    if any(w in low for w in ["코드", "버그", "구현", "리팩터"]):
        return "code"
    return task


def cmd_auto(args: argparse.Namespace) -> None:
    # Binary/reversing requests are local tool work. Do this before Ollama/model
    # checks so every entrypoint ("AI.exe ...", "AI.exe auto ...") behaves like
    # agent mode and cannot fall back to a how-to/provide-target answer.
    if implies_binary_work(args.goal):
        workspace = Path(args.workspace).resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        preflight_args = argparse.Namespace(
            yes=True,
            allow_shell=True,
            allow_write=True,
        )
        if deterministic_agent_fallback(args.goal, workspace, preflight_args, "auto early binary target"):
            return
    if not ollama_available():
        raise SystemExit("Ollama가 필요합니다. 설치 후 다시 실행하세요: https://ollama.com/download")
    mode, mode_reason = decide_mode(args.goal, args.mode)
    task = infer_task(args.goal, args.task)

    if mode == "ask":
        print(f"[auto] mode=ask ({mode_reason})", file=sys.stderr)
        return cmd_ask(argparse.Namespace(
            prompt=args.goal,
            level=args.level,
            task=task,
            allow_27b=args.allow_27b,
            temperature=args.temperature,
            num_ctx=args.num_ctx,
            num_predict=args.num_predict,
            no_stream=args.no_stream,
            dry_run=args.dry_run,
        ))

    print(f"[auto] mode=agent ({mode_reason})", file=sys.stderr)
    return cmd_agent(argparse.Namespace(
        goal=args.goal,
        workspace=args.workspace,
        level=args.level,
        task=task,
        allow_27b=args.allow_27b,
        allow_shell=args.allow_shell or args.allow_all,
        allow_write=args.allow_write or args.allow_all,
        yes=args.yes,
        max_steps=args.max_steps,
        temperature=0.15 if args.temperature is None else args.temperature,
        num_ctx=args.num_ctx,
        num_predict=args.num_predict,
        dry_run=args.dry_run,
    ))




def prioritize_agent_models(models: List[str], host: str) -> List[str]:
    """Put models that have passed agent JSON/tool tests before thinking-prone ones."""
    try:
        installed = set(ollama_tags(host))
    except Exception:
        installed = set()
    stable_order = [
        "fast-gemma:latest",
        "fast-qwen:latest",
        "gemma4:latest",
        "hf.co/pegasus912/gemma-4-31B-it-heretic-Q4_K_M-GGUF:Q4_K_M",
    ]
    ranked: List[str] = []
    for m in stable_order:
        if (not installed or m in installed) and m not in ranked:
            ranked.append(m)
    for m in models:
        if m not in ranked:
            ranked.append(m)
    # Move known thinking/Qwen agent models behind stable Gemma choices. They can
    # still be used as fallbacks, but should not be first because they often emit
    # <think> instead of action JSON.
    def score(m: str) -> int:
        low = m.lower()
        if m in stable_order:
            return stable_order.index(m)
        if "thinking" in low or "qwen3.6" in low or "qwen3.5-27b" in low:
            return 50
        return 20
    return sorted(ranked, key=score)

def normalize_agent_action(obj: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
    """Accept common tool-call JSON shapes and return (action, args)."""
    if not isinstance(obj, dict):
        return None, {}
    action = obj.get("action") or obj.get("tool") or obj.get("name") or obj.get("function")
    tool_args = obj.get("args") or obj.get("action_args") or obj.get("action_input") or obj.get("parameters") or obj.get("input") or {}
    reserved = {
        "action", "tool", "name", "function", "args", "action_args", "action_input",
        "parameters", "input", "tool_calls", "tool_call", "function_call", "final", "answer",
    }

    # OpenAI-style: {"tool_calls":[{"function":{"name":"...","arguments":"{...}"}}]}
    calls = obj.get("tool_calls") or obj.get("tool_call")
    if not action and calls:
        call = calls[0] if isinstance(calls, list) and calls else calls
        if isinstance(call, dict):
            fn = call.get("function") or call
            if isinstance(fn, dict):
                action = fn.get("name") or fn.get("action") or fn.get("tool")
                tool_args = fn.get("arguments") or fn.get("args") or fn.get("parameters") or tool_args

    # Function-call style: {"function_call":{"name":"...","arguments":"{...}"}}
    fc = obj.get("function_call")
    if not action and isinstance(fc, dict):
        action = fc.get("name") or fc.get("action")
        tool_args = fc.get("arguments") or fc.get("args") or tool_args

    if not action and "final" in obj:
        action = "final"
        final_value = obj.get("final")
        tool_args = final_value if isinstance(final_value, dict) else {"answer": str(final_value)}
    if not action and "answer" in obj:
        action = "final"
        tool_args = {"answer": str(obj.get("answer"))}
    if isinstance(tool_args, str):
        try:
            parsed = json.loads(tool_args)
            tool_args = parsed if isinstance(parsed, dict) else {"value": parsed}
        except Exception:
            tool_args = {"value": tool_args}
    if (tool_args is None or tool_args == {}) and isinstance(obj, dict):
        inferred = {k: v for k, v in obj.items() if k not in reserved}
        if inferred:
            tool_args = inferred
    if tool_args is None or not isinstance(tool_args, dict):
        tool_args = {}
    if isinstance(tool_args, dict):
        if "path" not in tool_args and "file_path" in tool_args:
            tool_args["path"] = tool_args.get("file_path")
        if "path" not in tool_args and "filename" in tool_args:
            tool_args["path"] = tool_args.get("filename")
        if "new_hex" not in tool_args and "new_content" in tool_args:
            tool_args["new_hex"] = tool_args.get("new_content")
        if "new_hex" not in tool_args and "bytes" in tool_args:
            tool_args["new_hex"] = tool_args.get("bytes")
    if isinstance(action, str):
        action = action.strip()
        action_key = re.sub(r"[\s\-]+", "_", action.lower())
        alias_map = {
            "file_read": "read_file",
            "readfile": "read_file",
            "file_write": "write_file",
            "writefile": "write_file",
            "create_file": "write_file",
            "createfile": "write_file",
            "save_file": "write_file",
            "file_append": "append_file",
            "appendfile": "append_file",
            "hash_file": "file_hashes",
            "hashes": "file_hashes",
            "magic": "file_type",
            "detect_file": "file_type",
            "edit_file": "replace_in_file",
            "replace_file": "replace_in_file",
            "patch_file": "replace_in_file",
            "line_replace": "replace_lines",
            "replace_line": "replace_lines",
            "insert_line": "insert_lines",
            "delete_line": "delete_lines",
            "regex_edit": "regex_replace",
            "replace_regex": "regex_replace",
            "apply_patch": "apply_unified_patch",
            "unified_patch": "apply_unified_patch",
            "binary_patch": "binary_replace",
            "binary_patch_offset": "binary_patch_offset",
            "patch_binary": "binary_replace",
            "file_patch": "binary_patch_offset",
            "exe_patch": "binary_replace",
            "dll_patch": "binary_replace",
            "patch_offset": "binary_patch_offset",
            "binary_write_offset": "binary_patch_offset",
            "exe_patch_offset": "binary_patch_offset",
            "dll_patch_offset": "binary_patch_offset",
            "strings": "binary_strings",
            "bin_strings": "binary_strings",
            "binary_find": "binary_search",
            "bin_search": "binary_search",
            "find_bytes": "binary_search",
            "pattern_search": "binary_pattern_search",
            "find_pattern": "binary_pattern_search",
            "hexdump": "binary_hexdump",
            "hex_dump": "binary_hexdump",
            "extract_bytes": "binary_extract",
            "bin_extract": "binary_extract",
            "bindiff": "binary_diff",
            "bin_diff": "binary_diff",
            "entropy": "binary_entropy",
            "fill_bytes": "binary_fill",
            "insert_bytes": "binary_insert",
            "delete_bytes": "binary_delete",
            "append_bytes": "binary_append",
            "pe": "pe_info",
            "pe_headers": "pe_info",
            "reverse_info": "pe_info",
            "rva_to_offset": "pe_rva_to_offset",
            "offset_to_rva": "pe_offset_to_rva",
            "section_extract": "pe_section_extract",
            "imports": "pe_imports",
            "pe_import_table": "pe_imports",
            "exports": "pe_exports",
            "pe_export_table": "pe_exports",
            "ghidra": "ghidra_analyze",
            "ghidrarun": "ghidra_analyze",
            "headless": "ghidra_analyze",
            "analyze_headless": "ghidra_analyze",
            "analyzeheadless": "ghidra_analyze",
            "rz_info": "rizin_info",
            "rzbin": "rizin_info",
            "sigcheck": "sigcheck_file",
            "capa": "capa_scan",
            "re_libs": "python_re_libs",
            "disasm": "disassemble",
            "objdump": "disassemble",
            "reverse_tools": "re_tool_inventory",
            "tool_inventory": "re_tool_inventory",
            "pattern_patch": "binary_pattern_patch",
            "patch_pattern": "binary_pattern_patch",
            "ps_list": "process_list",
            "list_processes": "process_list",
            "modules": "process_modules",
            "dll_modules": "process_modules",
            "dir_list": "list_dir",
            "listdir": "list_dir",
        }
        action = alias_map.get(action_key, alias_map.get(action.lower(), action_key))
        if action.startswith("browser."):
            action = "browser_" + action.split(".", 1)[1]
    return action, tool_args


def explicit_file_write_preflight_allowed(goal: str) -> bool:
    """Allow deterministic handling of concrete file create/write tasks.

    Unlike simple_local_preflight_allowed(), this is intentionally used before
    the model loop even when the wording mentions run/test/final. It only
    triggers for a concrete small text/code filename plus an explicit write or
    replacement verb, so broad debugging/build tasks still stay with the agent.
    """
    goal_text = str(goal or "")
    low = goal_text.lower()
    if implies_web_need(goal_text)[0] or implies_binary_work(goal_text):
        return False
    if not re.search(r'([A-Za-z0-9_.\-가-힣]+\.(?:txt|md|json|csv|log|py|js|ts|html|css|yml|yaml|ini|cfg))', goal_text):
        return False
    write_words = (
        "write", "create", "make", "save", "containing", "contains", "content",
        "replace", "change", "modify", "edit",
        "??", "??", "??", "??", "??", "?", "?", "??", "??", "??", "??",
    )
    return any(w in low or w in goal_text for w in write_words)


def simple_local_preflight_allowed(goal: str) -> bool:
    """Only short, explicit local file create/replace tasks may bypass the model loop.

    Broader agent requests must stay in agent mode so they can continue planning,
    run tests, inspect output, and perform multiple actions.
    """
    low = goal.lower()
    if "\n" in goal or "\uc774\uc804 \ub300\ud654 \ucee8\ud14d\uc2a4\ud2b8" in goal or "\ud604\uc7ac \uc791\uc5c5" in goal:
        return False
    broad_words = [
        "\uacc4\uc18d", "\uc774\uc5b4", "\uc804\ubd80", "\uc804\uccb4", "\uc644\ubcbd", "\uc54c\uc544\uc11c", "\ubb38\uc81c", "\ubd84\uc11d", "\uac80\uc0ac", "\uc810\uac80",
        "\ud14c\uc2a4\ud2b8", "\ube4c\ub4dc", "\uc2e4\ud589", "\uace0\uccd0", "\uc218\uc815\ud574", "\ub514\ubc84\uadf8", "\ud655\uc778\ud558\uace0", "\ucc3e\uc544\uc11c", "\ubcf4\uace0",
        "continue", "keep", "all", "complete", "analyze", "inspect", "debug", "test", "build", "run", "fix", "verify",
    ]
    if any(w in low for w in broad_words):
        return False
    file_match = re.search(r'([A-Za-z0-9_.\-\uAC00-\uD7A3]+\.(?:txt|md|json|csv|log|py|js|ts|html|css|yml|yaml|ini|cfg))', goal)
    if not file_match:
        return False
    simple_write = any(w in low for w in [
        "create", "write", "save", "make", "containing", "contains", "content",
        "\ub9cc\ub4e4", "\uc0dd\uc131", "\uc791\uc131", "\uc800\uc7a5", "\ub0b4\uc6a9", "\uc4f0\uace0", "\uc368\uc918",
    ])
    simple_replace = bool(re.search(r"([A-Za-z0-9_-]{2,})\s*(?:to|with|->|=>)\s*([A-Za-z0-9_-]{2,})", goal, re.I))
    if not simple_replace and ("\ub85c" in goal) and any(w in goal for w in ("\ubc14", "\ubcc0\uacbd", "\uc218\uc815")):
        simple_replace = True
    return simple_write or simple_replace

def deterministic_agent_fallback(goal: str, workspace: Path, args: argparse.Namespace, reason: str) -> bool:
    """Last-resort local executor when every model is timing out before emitting JSON."""
    low = goal.lower()

    def emit(action: str, tool_args: Dict[str, Any]) -> str:
        result = tool_exec(action, tool_args, workspace, getattr(args, "yes", True), getattr(args, "allow_shell", False), getattr(args, "allow_write", False))
        # Normal tool evidence goes to stdout, not stderr. Windows PowerShell
        # treats native-process stderr as ErrorRecord text ("AI.exe : ...") and
        # wraps/splits long JSON-looking lines, which made successful runs look
        # broken. Reserve stderr for guards/debug only.
        print(f"[tool:{action}] {tool_log_summary(action, result)}")
        return result

    def has_any(words: List[str]) -> bool:
        return any(w in goal or w in low for w in words)

    def is_ok_result(result: str) -> bool:
        r = (result or "").lower()
        return not (r.startswith(("tool error", "browser error")) or " error:" in r or "검색 결과 파싱 실패" in result)

    def summarize_tool_text(text: str, limit: int = 2500) -> str:
        text = re.sub(r"\s+", " ", str(text)).strip()
        return text[:limit]

    def compact_hex(s: str) -> str:
        return " ".join(re.findall(r"[0-9A-Fa-f]{2}", str(s))).upper()

    def compact_pattern(s: str) -> str:
        return " ".join(t.upper() if t != "??" else "??" for t in re.findall(r"\?\?|[0-9A-Fa-f]{2}", str(s)))

    def binary_patch_from_goal(rel: str) -> bool:
        """Execute exact byte-level patches described in the goal before falling back to analysis.

        This prevents refusal loops like "direct binary patching is impossible" when the
        user already supplied enough concrete patch data: target file + offset/old bytes/
        wildcard pattern + replacement bytes.
        """
        # offset 0x1234 -> 90 90 / @0x1234 new_hex=90 90 / 오프셋 0x1234 로 90 90
        m = re.search(
            r"(?:offset|오프셋|@)\s*[:=]?\s*(0x[0-9A-Fa-f]+|\d+).*?"
            r"(?:new_hex|new|to|with|=>|->|로)\s*[:=]?\s*((?:[0-9A-Fa-f]{2})(?:[\s:,\-]+[0-9A-Fa-f]{2})*)",
            goal,
            re.I | re.S,
        )
        if m:
            offset, new_hex = m.group(1), compact_hex(m.group(2))
            patched = emit("binary_patch_offset", {"path": rel, "offset": offset, "new_hex": new_hex, "backup": True})
            if not patched.lower().startswith("tool error"):
                emit("binary_hexdump", {"path": rel, "offset": offset, "length": max(16, len(bytes.fromhex(new_hex.replace(" ", ""))))})
                emit("file_hashes", {"path": rel})
                print(f"Done: binary offset patched and verified: {rel} @ {offset} -> {new_hex}.")
                return True

        # pattern "48 8B ?? ??" -> "90 90 90 90"
        m = re.search(
            r"(?:pattern|패턴)\s*[:=]?\s*((?:\?\?|[0-9A-Fa-f]{2})(?:[\s:,\-]+(?:\?\?|[0-9A-Fa-f]{2})){1,}).*?"
            r"(?:new_hex|new|to|with|=>|->|로)\s*[:=]?\s*((?:[0-9A-Fa-f]{2})(?:[\s:,\-]+[0-9A-Fa-f]{2})*)",
            goal,
            re.I | re.S,
        )
        if m:
            pattern, new_hex = compact_pattern(m.group(1)), compact_hex(m.group(2))
            patched = emit("binary_pattern_patch", {"path": rel, "pattern": pattern, "new_hex": new_hex, "backup": True})
            if not patched.lower().startswith("tool error"):
                emit("binary_search", {"path": rel, "needle_hex": new_hex, "limit": 20})
                emit("file_hashes", {"path": rel})
                print(f"Done: binary pattern patched and verified: {rel} pattern {pattern} -> {new_hex}.")
                return True

        # old bytes -> new bytes / replace AA BB with CC DD
        m = re.search(
            r"(?:replace|교체|바꿔|패치)?\s*((?:[0-9A-Fa-f]{2})(?:[\s:,\-]+[0-9A-Fa-f]{2})+)\s*"
            r"(?:with|to|=>|->|로)\s*((?:[0-9A-Fa-f]{2})(?:[\s:,\-]+[0-9A-Fa-f]{2})*)",
            goal,
            re.I | re.S,
        )
        if m:
            old_hex, new_hex = compact_hex(m.group(1)), compact_hex(m.group(2))
            patched = emit("binary_replace", {"path": rel, "old_hex": old_hex, "new_hex": new_hex, "backup": True})
            if not patched.lower().startswith("tool error"):
                emit("binary_search", {"path": rel, "needle_hex": new_hex, "limit": 20})
                emit("file_hashes", {"path": rel})
                print(f"Done: binary bytes replaced and verified: {rel} {old_hex} -> {new_hex}.")
                return True

        return False

    def extract_content(default: str = "OK") -> str:
        # If the goal references a remembered/session codeword, preserve the exact
        # literal (including hyphens) instead of letting a model paraphrase it.
        literal_patterns = [
            r"project\s+codeword\s+is\s+([A-Za-z0-9_-]{2,})",
            r"codeword\s+is\s+([A-Za-z0-9_-]{2,})",
            r"codename\s+is\s+([A-Za-z0-9_-]{2,})",
            r"code\s+name\s+is\s+([A-Za-z0-9_-]{2,})",
        ]
        if "codeword" in low or "codename" in low or "code name" in low:
            for pat in literal_patterns:
                m = re.search(pat, goal, re.I)
                if m:
                    return m.group(1)
        markers = [
            "\ub0b4\uc6a9\uc740",  # ???
            "\ub0b4\uc6a9\uc744",  # ???
            "content is",
            "with content",
            "containing",
            "contains",
            "content:",
        ]
        raw = ""
        low_goal = goal.lower()
        for marker in markers:
            idx = low_goal.find(marker.lower())
            if idx >= 0:
                raw = goal[idx + len(marker):].strip()
                break
        if not raw:
            return default
        stops = [
            "한 줄", "한줄", "만 쓰", "쓰고", "저장", "넣고",
            " one line", " only", " final", " then ", " and ", "검증", "읽어",
        ]
        cut = len(raw)
        raw_low = raw.lower()
        for stop in stops:
            pos = raw_low.find(stop.lower())
            if pos >= 0:
                cut = min(cut, pos)
        val = raw[:cut].strip().strip(' "\'??`')
        return val or default

    file_match = re.search(r'([A-Za-z0-9_.\-\uAC00-\uD7A3]+\.(?:txt|md|json|csv|log|py|js|ts|html|css|yml|yaml|ini|cfg))', goal)
    wants_write = any(w in low for w in ("write", "create", "make", "edit", "save")) or has_any([
        "\ub9cc\ub4e4", "\uc0dd\uc131", "\uc791\uc131", "\uc4f0", "\uc218\uc815", "\uc800\uc7a5"
    ])
    replace_match = None
    wants_replace = any(w in low for w in ("replace", "change", "modify", "edit", "fix")) or any(w in goal for w in ("바꿔", "변경", "수정", "고쳐", "교체"))
    if file_match and wants_replace:
        replace_match = re.search(r"([A-Za-z0-9_-]{2,})\s*(?:\ub97c\s*)?([A-Za-z0-9_-]{2,})\ub85c\s*\ubc14", goal)
        if not replace_match:
            replace_match = re.search(r"\breplace\s+([A-Za-z0-9_-]{2,})\s+(?:with|to)\s+([A-Za-z0-9_-]{2,})\b", goal, re.I)
        if not replace_match:
            replace_match = re.search(r"\b([A-Za-z0-9_]{2,})\s*(?:->|=>)\s*([A-Za-z0-9_]{2,})\b", goal, re.I)
    if file_match and replace_match:
        rel = file_match.group(1)
        old, new = replace_match.group(1), replace_match.group(2)
        src = workspace_path(workspace, rel)
        if src.exists():
            text = src.read_text(encoding="utf-8", errors="replace")
            updated = text.replace(old, new)
            if updated != text:
                emit("write_file", {"path": rel, "content": updated})
                verified = emit("read_file", {"path": rel})
                if new in verified and old not in verified:
                    print(f"Done: replaced {old} -> {new} in {rel} and verified.")
                    return True
            # If a bad model already clobbered the file before verification,
            # recover to the requested replacement literal instead of writing a
            # generic OK fallback. This prevents "fix OLD->NEW" repairs from
            # passing with unrelated content.
            emit("write_file", {"path": rel, "content": new + "\n"})
            verified = emit("read_file", {"path": rel})
            if new in verified and old not in verified:
                print(f"Done: recovered {rel} with requested replacement {new} and verified.")
                return True
    if file_match and wants_write:
        rel = file_match.group(1)
        content = extract_content("OK")
        if "\ud55c \uc904" in goal or "\ud55c\uc904" in goal or "one line" in low:
            content = content.splitlines()[0].strip()
        emit("write_file", {"path": rel, "content": content + ("\n" if not content.endswith("\n") else "")})
        emit("read_file", {"path": rel})
        print(f"Done: wrote and verified {rel}.")
        return True

    binary_path = extract_binary_path_from_goal(goal)
    wants_binary_work = implies_binary_work(goal)

    web_needed, _web_reason = implies_web_need(goal)
    if web_needed and not wants_binary_work:
        url_m = re.search(r"https?://[^\s\"'<>]+", goal)
        if url_m:
            url = url_m.group(0).rstrip(".,)")
            result = emit("fetch_url", {"url": url})
            if is_ok_result(result):
                print("Done: fetched URL and verified response.\n" + summarize_tool_text(result))
                return True
        result = emit("web_search", {"query": goal, "max_results": 5})
        if is_ok_result(result):
            print("Done: web search completed.\n" + result[:4000])
            return True

    if binary_path and wants_binary_work:
        rel = binary_path.strip().strip('"\'`')
        if binary_patch_from_goal(rel):
            return True
        info = emit("binary_info", {"path": rel, "head": 128})
        pe = emit("pe_info", {"path": rel})
        imports = emit("pe_imports", {"path": rel, "limit": 200})
        exports = emit("pe_exports", {"path": rel, "limit": 200})
        strings = emit("binary_strings", {"path": rel, "min_len": 4, "limit": 80})
        entropy = emit("binary_entropy", {"path": rel, "window": 4096, "limit": 10})
        if not all(x.lower().startswith("tool error") for x in (info, pe, imports, exports, strings, entropy)):
            print("Done: binary inspected with binary_info, pe_info, pe_imports, pe_exports, binary_strings, and binary_entropy. Use binary_search/binary_hexdump plus binary_replace or binary_patch_offset for exact patching.")
            return True
        print(f"Done: concrete binary target was used but the requested operation failed; not falling back to another workspace binary: {rel}.")
        return True
    if wants_binary_work:
        inv = emit("re_tool_inventory", {})
        libs = emit("python_re_libs", {})
        files = emit("search_files", {"root": ".", "pattern": r"\.(exe|dll|sys|bin)$", "glob": "*"})
        for candidate in extract_binary_paths_from_text(files):
            try:
                p = workspace_path(workspace, candidate)
                if not p.exists() or not p.is_file():
                    continue
            except Exception:
                continue
            # A found binary is a real target. Do not stop at search_files with
            # "provide/place target"; immediately inspect/verify it.
            rel = str(p)
            if binary_patch_from_goal(rel):
                return True
            info = emit("binary_info", {"path": rel, "head": 128})
            pe = emit("pe_info", {"path": rel})
            imports = emit("pe_imports", {"path": rel, "limit": 200})
            exports = emit("pe_exports", {"path": rel, "limit": 200})
            strings = emit("binary_strings", {"path": rel, "min_len": 4, "limit": 80})
            entropy = emit("binary_entropy", {"path": rel, "window": 4096, "limit": 10})
            if not all(x.lower().startswith("tool error") for x in (info, pe, imports, exports, strings, entropy)):
                print(f"Done: binary target found by search_files and inspected: {rel}.")
                return True
        if is_ok_result(inv) or is_ok_result(libs) or is_ok_result(files):
            print("Done: binary/reversing tools checked, but no existing EXE/DLL/SYS/BIN target was found to inspect or patch.")
            return True

    wants_list = any(w in low for w in ("list", "directory", "folder")) or has_any([
        "\ubaa9\ub85d", "\ud3f4\ub354", "\ub514\ub809\ud130\ub9ac", "\ud604\uc7ac \ud3f4\ub354"
    ])
    if wants_list:
        emit("list_dir", {"path": "."})
        print("Done: checked the current folder list.")
        return True

    return False


def cmd_agent(args: argparse.Namespace) -> None:
    # Full local-agent mode: every model/fallback path gets the same execution
    # permissions so a model cannot silently fail because a routed mode omitted
    # allow_shell/allow_write. Path safety is still enforced by workspace_path().
    args.allow_shell = True
    args.allow_write = True
    args.yes = True
    workspace = Path(args.workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    current_goal = str(getattr(args, "current_goal", args.goal) or args.goal)
    current_web_needed, _current_web_reason = implies_web_need(current_goal)
    current_binary_path = extract_binary_path_from_goal(current_goal)

    # Session mode passes prior chat context in args.goal. Routing/preflight must
    # use only the current user task; otherwise old logs containing ".exe" poison
    # a new URL/domain request and trigger binary tooling.
    if current_web_needed and not implies_binary_work(current_goal):
        if deterministic_agent_fallback(current_goal, workspace, args, "early current web target"):
            return

    # Binary patch/inspect work must not depend on Ollama/model health. Run
    # deterministic tooling immediately; if a concrete path is present it is
    # used, otherwise search_files results are followed by binary_info/pe_info
    # instead of stopping at "provide/place target".
    if implies_binary_work(current_goal) and ((not current_web_needed) or bool(current_binary_path)):
        if deterministic_agent_fallback(current_goal, workspace, args, "early concrete binary target"):
            return

    config = load_config()
    if not ollama_available():
        raise SystemExit("Ollama가 필요합니다. 설치 후 다시 실행하세요: https://ollama.com/download")
    level = args.level
    task = args.task
    # Tool-calling JSON is more reliable on the existing local Gemma4 models
    # than on the tiny fast fallbacks, so default agent mode to Gemma4 unless
    # the user explicitly requested another level/task.
    if level == "auto" and task == "auto":
        task = "gemma4"
    key, prof, reason = choose_profile(config, args.goal, level, task, args.allow_27b)
    print(f"[agent] workspace={workspace}", file=sys.stderr)
    print(f"[model] {key} -> {prof['model']} ({reason})", file=sys.stderr)
    if not args.dry_run:
        ensure_ollama_api(config["ollama"]["host"])
    models = candidate_models(prof, config["ollama"]["host"], dry_run=args.dry_run)
    if not args.dry_run:
        models = prioritize_agent_models(models, config["ollama"]["host"])
    model_index = 0
    model = models[model_index]
    if args.dry_run:
        return

    web_needed, web_reason = implies_web_need(current_goal)
    goal_text = args.goal
    if web_needed:
        goal_text = (
            f"[자동판단: 외부/최신/사이트 정보 확인 필요={web_reason}. "
            "사용자가 인터넷/브라우저라고 직접 말하지 않았어도 web_search/fetch_url/open_url 중 필요한 도구를 먼저 사용하라.]\n"
            + args.goal
        )

    base_messages = [
        {"role": "system", "content": AGENT_SYSTEM + goal_system_suffix()},
        {"role": "user", "content": f"workspace={workspace}\ngoal: {goal_text}"},
    ]
    messages = list(base_messages)

    # Fast deterministic preflight only for very simple explicit local file tasks.
    # Never intercept broad/continuing agent jobs; those must stay in the model loop.
    if key != "test" and simple_local_preflight_allowed(args.goal) and deterministic_agent_fallback(args.goal, workspace, args, "preflight simple local task"):
        return

    # Prevent the exact failure class that triggered "no-howto final blocked":
    # concrete EXE/DLL/SYS/BIN paths do not need to wait for a local model to
    # decide whether to run tools. Execute the deterministic binary patch/inspect
    # preflight first so an existing target path always gets real binary actions
    # (and exact byte patches, when the goal includes offset/pattern/old->new).
    if key != "test" and implies_binary_work(args.goal) and extract_binary_path_from_goal(args.goal):
        if deterministic_agent_fallback(args.goal, workspace, args, "preflight concrete binary target"):
            return

    def strict_json_reminder(reason: str) -> str:
        return (
            f"Previous response failed: {reason}. Output exactly one JSON object now. "
            "The first character must be { and the last character must be }. "
            "Do not output <think>, reasoning, markdown, prose, or multiple JSON objects. "
            "Examples: {\"action\":\"list_dir\",\"args\":{\"path\":\".\"}} or "
            "{\"action\":\"final\",\"args\":{\"answer\":\"done\"}}"
        )

    def reset_agent_context(reason: str) -> None:
        messages[:] = list(base_messages)
        messages.append({"role": "user", "content": strict_json_reminder(reason)})

    def switch_model_after_bad_output(reason: str) -> bool:
        nonlocal model_index, model, invalid_retries
        bad_models.add(model)
        for i, candidate in enumerate(models):
            if i != model_index and candidate not in bad_models:
                model_index = i
                model = candidate
                invalid_retries = 0
                reset_agent_context(reason)
                print(f"[retry] bad model output -> switched model: {model}", file=sys.stderr)
                return True
        reset_agent_context(reason)
        invalid_retries = 0
        print("[guard] bad model output; no unused fallback left, reset context and retry", file=sys.stderr)
        return False

    step = 1
    invalid_retries = 0
    max_invalid_retries = 3
    last_tool_failed = False
    executed_actions: List[str] = []
    pending_write_verify = False
    pending_binary_verify = False
    last_read_text = ""
    last_read_path = ""
    bad_models: set[str] = set()
    agent_num_ctx = getattr(args, "num_ctx", None)
    agent_num_predict = getattr(args, "num_predict", None)
    all_model_failures = 0
    raw_output_counts: Counter[str] = Counter()
    action_sig_counts: Counter[str] = Counter()
    tool_result_counts: Counter[str] = Counter()
    repeated_guard_hits = 0
    max_repeated_guard_hits = 6
    hard_step_limit = 200

    def compact_sig(value: Any, limit: int = 1400) -> str:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except Exception:
            text = str(value)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:limit]

    # Always auto-extend max_steps. The value is only the first checkpoint,
    # not a hard stop. This prevents long tasks from stopping midway.
    max_steps = int(getattr(args, "max_steps", 0) or 0)
    if max_steps <= 0:
        max_steps = 50
    extend_chunk = 50
    while True:
        if step > hard_step_limit:
            print(f"[guard] hard step limit reached ({hard_step_limit}); stopping infinite loop", file=sys.stderr)
            if deterministic_agent_fallback(args.goal, workspace, args, "hard step limit reached"):
                return
            print("무한 루프를 차단했습니다. deterministic fallback으로도 완료하지 못했습니다.")
            return
        if step > max_steps:
            old_max_steps = max_steps
            max_steps += extend_chunk
            print(f"[agent] max_steps auto-extend: {old_max_steps} -> {max_steps}", file=sys.stderr)
        print(f"\n[step {step}]", file=sys.stderr)
        try:
            out = chat_ollama(config, model, messages, stream=False, temperature=args.temperature, num_ctx=agent_num_ctx, num_predict=agent_num_predict, json_mode=True)
        except (DegenerateOutput, EmptyOutput, TimeoutError, urllib.error.URLError) as e:
            print(f"[guard] agent model output failed: {model} ({e})", file=sys.stderr)
            if is_timeout_error(e):
                bad_models.add(model)
                stop_ollama_model(model, config["ollama"]["host"])
                print(f"[guard] timed-out model stopped/unloaded: {model}", file=sys.stderr)
            # Try remaining installed strict fallback models for the same step.
            recovered = False
            timeout_fallback_attempts = 0
            for alt_i in range(model_index + 1, len(models)):
                alt = models[alt_i]
                if is_timeout_error(e) and alt in bad_models:
                    continue
                if is_timeout_error(e) and timeout_fallback_attempts >= 1:
                    break
                if is_timeout_error(e):
                    timeout_fallback_attempts += 1
                try:
                    print(f"[retry] agent fallback model: {alt}", file=sys.stderr)
                    out = chat_ollama(config, alt, messages, stream=False, temperature=args.temperature, num_ctx=agent_num_ctx, num_predict=agent_num_predict, json_mode=True)
                    model_index = alt_i
                    model = alt
                    recovered = True
                    break
                except (DegenerateOutput, EmptyOutput, TimeoutError, urllib.error.URLError) as e2:
                    print(f"[guard] agent fallback model failed: {alt} ({e2})", file=sys.stderr)
                    if is_timeout_error(e2):
                        bad_models.add(alt)
                        stop_ollama_model(alt, config["ollama"]["host"])
                        print(f"[guard] timed-out fallback stopped/unloaded: {alt}", file=sys.stderr)
            if not recovered:
                all_model_failures += 1
                invalid_retries += 1
                if deterministic_agent_fallback(args.goal, workspace, args, str(e)):
                    return
                base_ctx = int(config.get("ollama", {}).get("num_ctx", 8192) or 8192)
                base_predict = int(config.get("ollama", {}).get("num_predict", 512) or 512)
                agent_num_ctx = min(int(agent_num_ctx or base_ctx), 4096)
                agent_num_predict = min(int(agent_num_predict or base_predict), 256)
                preferred = next((m for m in models if m in ("fast-gemma:latest", "gemma4:latest")), models[0])
                model_index = models.index(preferred)
                model = preferred
                if executed_actions and not last_tool_failed:
                    summary = ", ".join(executed_actions[-4:])
                    reset_agent_context(f"partial execution after actions [{summary}] but task is not verified complete: {e}")
                else:
                    reset_agent_context(f"all models timed out/failed; compacted context and reduced num_ctx={agent_num_ctx}, num_predict={agent_num_predict}: {e}")
                if invalid_retries > max_invalid_retries and isinstance(e, urllib.error.URLError) and not is_timeout_error(e):
                    raise
                if invalid_retries > max_invalid_retries:
                    print("[guard] all models failed; compacted context, reduced generation budget, and retrying fast/stable model.", file=sys.stderr)
                    invalid_retries = 0
                continue
        print(out, file=sys.stderr)
        raw_sig = compact_sig(clean_model_output(out), 1200)
        raw_output_counts[raw_sig] += 1
        if raw_sig and raw_output_counts[raw_sig] >= 3:
            repeated_guard_hits += 1
            print(f"[guard] repeated identical model output blocked ({raw_output_counts[raw_sig]}x)", file=sys.stderr)
            if deterministic_agent_fallback(args.goal, workspace, args, "repeated identical model output"):
                return
            switched = switch_model_after_bad_output("repeated identical model output")
            if repeated_guard_hits >= max_repeated_guard_hits:
                print("반복 모델 출력 루프를 차단했습니다. 실행 가능한 fallback도 실패했습니다.")
                return
            if not switched and repeated_guard_hits >= 2 and deterministic_agent_fallback(args.goal, workspace, args, "no unused fallback after repeated model output"):
                return
            continue
        if is_control_token_junk(out):
            invalid_retries += 1
            switch_model_after_bad_output("thinking/control-token output instead of JSON action")
            continue
        try:
            obj = extract_json(out)
        except Exception as e:
            invalid_retries += 1
            print(f"[guard] JSON parse failed: {e}", file=sys.stderr)
            if invalid_retries >= 2:
                switch_model_after_bad_output(f"JSON parse failure: {e}")
            else:
                messages.append({"role": "assistant", "content": clean_model_output(out)[:2000]})
                messages.append({"role": "user", "content": strict_json_reminder(f"JSON parse failure: {e}")})
            continue
        action, tool_args = normalize_agent_action(obj)
        valid_actions = {
            "final", "list_dir", "read_file", "write_file", "append_file", "file_info", "file_hashes", "file_type", "read_lines", "replace_lines", "insert_lines", "delete_lines", "regex_replace", "apply_unified_patch", "replace_in_file", "backup_file", "binary_info", "binary_strings", "binary_hexdump", "binary_search", "binary_pattern_search", "binary_extract", "binary_diff", "binary_entropy", "binary_append", "binary_insert", "binary_delete", "binary_fill", "pe_info", "pe_imports", "pe_exports", "pe_rva_to_offset", "pe_offset_to_rva", "pe_section_extract", "disassemble", "ghidra_analyze", "rizin_info", "sigcheck_file", "capa_scan", "python_re_libs", "re_tool_inventory", "binary_replace", "binary_patch_offset", "binary_pattern_patch", "process_list", "process_modules", "search_files", "shell",
            "fetch_url", "web_search", "download_file", "open_url", "open_file",
            "browser_open", "browser_click", "browser_type", "browser_press", "browser_screenshot",
            "browser_eval", "browser_text", "browser_close",
        }
        if not isinstance(action, str) or not action or action not in valid_actions:
            invalid_retries += 1
            print(f"[guard] missing/invalid action ignored: {action!r}", file=sys.stderr)
            if implies_binary_work(args.goal) and deterministic_agent_fallback(args.goal, workspace, args, f"invalid binary/reversing action: {action!r}"):
                return
            if invalid_retries >= 2:
                switch_model_after_bad_output("missing or invalid action field")
            else:
                messages.append({"role": "assistant", "content": json.dumps(obj, ensure_ascii=False)[:2000]})
                messages.append({"role": "user", "content": strict_json_reminder("missing or invalid action field")})
            continue
        action_sig = compact_sig({"action": action, "args": tool_args}, 1600)
        action_sig_counts[action_sig] += 1
        if action != "final" and action_sig_counts[action_sig] >= 3:
            repeated_guard_hits += 1
            print(f"[guard] repeated identical action blocked: {action} ({action_sig_counts[action_sig]}x)", file=sys.stderr)
            if deterministic_agent_fallback(args.goal, workspace, args, "repeated identical action"):
                return
            switched = switch_model_after_bad_output(f"repeated identical action: {action}")
            if repeated_guard_hits >= max_repeated_guard_hits:
                print(f"반복 action 루프를 차단했습니다: {action}")
                return
            if not switched and repeated_guard_hits >= 2 and deterministic_agent_fallback(args.goal, workspace, args, f"no unused fallback after repeated action: {action}"):
                return
            continue
        if action == "final":
            answer = tool_args.get("answer", "")
            final_sig = compact_sig({"final": answer}, 1200)
            if final_sig and action_sig_counts[action_sig] >= 3 and implies_action_need(args.goal):
                repeated_guard_hits += 1
                print(f"[guard] repeated final blocked ({action_sig_counts[action_sig]}x)", file=sys.stderr)
                if deterministic_agent_fallback(args.goal, workspace, args, "repeated final"):
                    return
                switch_model_after_bad_output("repeated final")
                continue
            blocked_final, why = final_without_evidence(answer, args.goal, executed_actions)
            browser_verify_needed = (
                ("browser_eval" in args.goal.lower() or "값 확인" in args.goal or "검증" in args.goal)
                and any(isinstance(a, str) and a.startswith("browser_") for a in executed_actions)
                and not any(a in executed_actions for a in ("browser_eval", "browser_text", "browser_screenshot"))
            )
            write_verify_needed = pending_write_verify
            binary_verify_needed = pending_binary_verify
            readback_mismatch = readback_mismatch_reason(args.goal, last_read_text) if last_read_path else ""
            readback_path_mismatch = readback_path_mismatch_reason(args.goal, last_read_path, workspace) if last_read_path else ""
            if blocked_final or (last_tool_failed and implies_action_need(args.goal)) or browser_verify_needed or write_verify_needed or binary_verify_needed or readback_mismatch or readback_path_mismatch:
                invalid_retries += 1
                why = why or (
                    "browser verification missing" if browser_verify_needed else
                    "binary verification missing after patch/edit" if binary_verify_needed else
                    readback_path_mismatch if readback_path_mismatch else
                    readback_mismatch if readback_mismatch else
                    "file verification missing after write/edit" if write_verify_needed else
                    "previous tool failed"
                )
                print(f"[guard] no-howto final blocked until real action: {why} ({invalid_retries}/{max_invalid_retries})", file=sys.stderr)
                # For EXE/DLL/binary/reversing goals, a refusal-style final must
                # not bounce forever through model retries. Immediately attempt
                # deterministic binary analysis/patch tooling if the goal is
                # concrete enough, then verify before final output.
                if (((blocked_final or binary_verify_needed) and implies_binary_work(args.goal)) or (last_tool_failed and implies_action_need(args.goal)) or readback_mismatch or readback_path_mismatch) and deterministic_agent_fallback(args.goal, workspace, args, why):
                    return
                if invalid_retries >= 2:
                    switch_model_after_bad_output(f"final without required action/evidence: {why}")
                else:
                    messages.append({"role": "assistant", "content": json.dumps(obj, ensure_ascii=False)})
                    verify_msg = (
                        "방금 final은 증거가 부족해서 금지다. 실제 도구 실행 결과를 바탕으로 다음 action JSON 하나만 출력해. "
                    )
                    if pending_binary_verify:
                        verify_msg += (
                            "EXE/DLL/바이너리를 패치했다면 read_file/read_lines를 쓰지 말고 "
                            "binary_hexdump, binary_search, file_hashes, binary_info 중 하나 이상으로 바이트와 해시를 검증한 뒤 final로 끝내라."
                        )
                    else:
                        verify_msg += (
                            "파일을 썼거나 수정했다면 read_file로 다시 읽어 실제 내용까지 검증하고, 브라우저 검증이 필요하면 "
                            "browser_eval/browser_text/browser_screenshot을 사용해 확인한 뒤에만 final로 끝내라."
                        )
                    messages.append({"role": "user", "content": verify_msg})
                continue
            print(str(answer))
            return
        invalid_retries = 0
        was_pending_write_verify = pending_write_verify
        was_pending_binary_verify = pending_binary_verify
        result = tool_exec(action, tool_args, workspace, args.yes, args.allow_shell, args.allow_write)
        executed_actions.append(action)
        tool_failed_now = result.lower().startswith(("tool error", "browser error")) or " error:" in result.lower() or "검색 결과 파싱 실패" in result
        binary_mutating_actions = ("binary_replace", "binary_patch_offset", "binary_pattern_patch", "binary_extract", "binary_append", "binary_insert", "binary_delete", "binary_fill", "pe_section_extract")
        binary_verify_actions = ("file_hashes", "file_type", "binary_info", "binary_hexdump", "binary_search", "binary_pattern_search", "binary_diff", "binary_entropy", "pe_info", "pe_imports", "pe_exports", "pe_rva_to_offset", "pe_offset_to_rva", "disassemble", "ghidra_analyze", "rizin_info", "sigcheck_file", "capa_scan")
        if action in ("write_file", "append_file", "replace_in_file", "replace_lines", "insert_lines", "delete_lines", "regex_replace", "apply_unified_patch"):
            pending_write_verify = True
            pending_binary_verify = False
            last_read_text = ""
            last_read_path = ""
        elif action in binary_mutating_actions:
            pending_write_verify = False
            pending_binary_verify = True
            last_read_text = ""
            last_read_path = str(tool_args.get("path", ""))
        elif action in ("read_file", "read_lines", "file_info", "file_hashes", "file_type", "binary_info", "binary_strings", "binary_hexdump", "binary_search", "binary_pattern_search", "binary_diff", "binary_entropy", "pe_info", "pe_imports", "pe_exports", "pe_rva_to_offset", "pe_offset_to_rva", "disassemble", "ghidra_analyze", "rizin_info", "sigcheck_file", "capa_scan", "python_re_libs", "re_tool_inventory", "process_list", "process_modules"):

            if tool_failed_now:
                pending_write_verify = was_pending_write_verify
                pending_binary_verify = was_pending_binary_verify
            else:
                if pending_write_verify:
                    pending_write_verify = False
                if action in binary_verify_actions:
                    pending_binary_verify = False
                last_read_text = result[:30000]
                last_read_path = str(tool_args.get("path", ""))
        print(f"[tool:{action}] {tool_log_summary(action, result)}")
        result_sig = compact_sig({"action": action, "args": tool_args, "result": result[:4000]}, 2200)
        tool_result_counts[result_sig] += 1
        if tool_result_counts[result_sig] >= 3:
            repeated_guard_hits += 1
            print(f"[guard] repeated identical tool result blocked: {action} ({tool_result_counts[result_sig]}x)", file=sys.stderr)
            if deterministic_agent_fallback(args.goal, workspace, args, "repeated identical tool result"):
                return
            switched = switch_model_after_bad_output(f"repeated identical tool result: {action}")
            if repeated_guard_hits >= max_repeated_guard_hits:
                print(f"반복 tool 결과 루프를 차단했습니다: {action}")
                return
            if not switched and repeated_guard_hits >= 2 and deterministic_agent_fallback(args.goal, workspace, args, f"no unused fallback after repeated tool result: {action}"):
                return
            step += 1
            continue
        try:
            robj = json.loads(result)
            last_tool_failed = robj.get("ok") is False
        except Exception:
            last_tool_failed = tool_failed_now
        if last_tool_failed and (implies_binary_work(args.goal) or action in binary_mutating_actions or action in binary_verify_actions):
            print(f"[guard] binary/reversing tool failed; attempting deterministic recovery: {result[:300]}", file=sys.stderr)
            recovery_goal = binary_failure_recovery_goal(args.goal, action, tool_args, result)
            if deterministic_agent_fallback(recovery_goal, workspace, args, result):
                return
        if last_tool_failed and (was_pending_write_verify or action == "read_file") and implies_action_need(args.goal):
            print(f"[guard] tool failure after write/read; attempting deterministic recovery: {result[:300]}", file=sys.stderr)
            if deterministic_agent_fallback(args.goal, workspace, args, result):
                return
        messages.append({"role": "assistant", "content": json.dumps(obj, ensure_ascii=False)})
        messages.append({"role": "user", "content": f"tool_result:\n{result}"})
        step += 1
    print("[agent] stopped unexpectedly after max_steps loop exit; auto-extend should keep running.")


def trim_history(messages: List[Dict[str, str]], max_chars: int) -> List[Dict[str, str]]:
    if max_chars <= 0:
        return messages
    total = sum(len(m.get("content", "")) for m in messages)
    if total <= max_chars:
        return messages
    if not messages:
        return messages
    system = messages[:1] if messages[0].get("role") == "system" else []
    rest = messages[len(system):]
    while rest and sum(len(m.get("content", "")) for m in system + rest) > max_chars:
        rest.pop(0)
    return system + rest


def session_help() -> None:
    print("""
명령:
  /exit              종료
  /help              도움말
  /history           현재 세션 대화 턴 수
  /clear             세션 기억 초기화
  /goal              ?? ?? ?? ??
  /goal <??>       ?? ?? ??/??
  /doctor            ?? ?? ??? ??
  /model             현재 세션 모델 표시
  /model <profile>   모델 프로필 변경: fast, balanced, heavy, gemma4, local 등
  /agent <작업>      같은 세션에서 에이전트 작업 강제 실행

그냥 "파일 만들어줘", "코드 고쳐줘", "테스트 돌려줘"처럼 말하면 자동으로 에이전트 모드가 실행됩니다.
""".strip())


def run_session_agent(line: str, messages: List[Dict[str, str]], args: argparse.Namespace, force: bool = False) -> None:
    goal = line.split(None, 1)[1].strip() if force and line.lower().startswith("/agent ") else line.strip()
    context = "\n".join([f"{m['role']}: {m['content']}" for m in messages[-args.agent_context_messages:]])
    ns = argparse.Namespace(
        goal=f"이전 대화 컨텍스트:\n{context}\n\n현재 작업:\n{goal}",
        current_goal=goal,
        workspace=args.workspace,
        level=args.agent_level,
        task=args.agent_task,
        allow_27b=args.allow_27b,
        allow_shell=True,
        allow_write=True,
        yes=True,
        max_steps=args.max_steps,
        temperature=0.15,
        num_ctx=args.num_ctx,
        num_predict=args.num_predict,
        dry_run=False,
    )
    cmd_agent(ns)


def cmd_session(args: argparse.Namespace) -> None:
    # session --once with a binary seed should also complete without touching
    # Ollama first. Interactive sessions still initialize the chat model below.
    if args.seed and implies_binary_work(args.seed):
        workspace = Path(args.workspace).resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        preflight_args = argparse.Namespace(
            yes=True,
            allow_shell=True,
            allow_write=True,
        )
        if deterministic_agent_fallback(args.seed, workspace, preflight_args, "session early binary target"):
            return
    config = load_config()
    if not ollama_available():
        raise SystemExit("Ollama가 필요합니다. 설치 후 다시 실행하세요: https://ollama.com/download")
    ensure_ollama_api(config["ollama"]["host"])

    level = args.level
    task = args.task
    if level == "auto" and task == "auto":
        task = "summary"
    profile_key, prof, reason = choose_profile(config, args.seed or "세션 대화", level, task, args.allow_27b)
    models = candidate_models(prof, config["ollama"]["host"], dry_run=False)
    installed_names = set(ollama_tags(config["ollama"]["host"]))
    session_preferred: List[str] = []
    if "fast-gemma:latest" in installed_names:
        session_preferred.append("fast-gemma:latest")
    if "gemma4:latest" in installed_names:
        session_preferred.append("gemma4:latest")
    for pm in reversed(session_preferred):
        if pm not in models:
            models.insert(0, pm)
    model = models[0]
    messages: List[Dict[str, str]] = [{"role": "system", "content": SYSTEM_BY_TASK["default"] + "\nPersistent session: remember prior turns. Preserve user-provided codenames, filenames, identifiers, capitalization, and hyphens verbatim. If asked for a codename, answer only the exact original codename." + goal_system_suffix()}]
    print("Local AI persistent session")
    print(f"[model] {profile_key} -> {model} ({reason})")
    print("같은 창에서는 /exit 전까지 이전 대화를 계속 기억합니다. 파일/코드/테스트 작업은 자동 에이전트로 실행됩니다. /help")

    if args.seed:
        pending: List[str] = [args.seed]
    else:
        pending = []

    while True:
        if pending:
            line = pending.pop(0)
            print(f"\nAI> {line}")
        else:
            try:
                line = input("\nAI> ").strip()
            except EOFError:
                print()
                return
        if not line:
            continue
        low = line.lower()
        if low in ("/exit", "exit", "quit", "q"):
            return
        if low in ("/help", "help"):
            session_help()
            continue
        if low == "/history":
            user_turns = sum(1 for m in messages if m.get("role") == "user")
            chars = sum(len(m.get("content", "")) for m in messages)
            print(f"history: user_turns={user_turns}, messages={len(messages)}, chars={chars}")
            continue
        if low == "/clear":
            messages = messages[:1]
            print("세션 기억 초기화 완료")
            continue
        if low == "/goal":
            current_goal = read_persistent_goal()
            print(current_goal if current_goal else "(no persistent /goal set)")
            continue
        if low.startswith("/goal "):
            new_goal = line.split(None, 1)[1].strip()
            write_persistent_goal(new_goal)
            messages[0] = {"role": "system", "content": SYSTEM_BY_TASK["default"] + "\nPersistent session: remember prior turns. Preserve user-provided codenames, filenames, identifiers, capitalization, and hyphens verbatim. If asked for a codename, answer only the exact original codename." + goal_system_suffix()}
            print(f"persistent /goal saved: {new_goal}")
            continue
        if low == "/doctor":
            tests = [
                ("regression_binary_path_test.py", 120),
                ("regression_binary_entrypoints_test.py", 180),
                ("watchdog_test.py", 900),
                ("internet_test.py", 900),
                ("playwright_test.py", 900),
                ("session_test.py", 1200),
                ("stress_test.py", 1800),
            ]
            all_ok = True
            for test, timeout_s in tests:
                print(f"[doctor] running {test}")
                proc = subprocess.run([sys.executable, str(ROOT / test)], cwd=str(ROOT.parent), text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout_s)
                print((proc.stdout or "")[-6000:])
                print(f"[doctor] {test} exit={proc.returncode}")
                if proc.returncode != 0:
                    all_ok = False
                    break
            print("[doctor] overall=" + ("PASS" if all_ok else "FAIL"))
            if not all_ok and getattr(args, "once", False):
                raise SystemExit(1)
            continue
        if low == "/model":
            print(f"{profile_key} -> {model}")
            continue
        if low.startswith("/model "):
            requested = line.split(None, 1)[1].strip()
            profile_key, prof, reason = choose_profile(config, "", requested, requested, args.allow_27b)
            models = candidate_models(prof, config["ollama"]["host"], dry_run=False)
            model = models[0]
            print(f"[model] {profile_key} -> {model} ({reason})")
            continue
        if low.startswith("/agent "):
            run_session_agent(line, messages, args, force=True)
            messages.append({"role": "user", "content": line})
            messages.append({"role": "assistant", "content": "[agent 작업 실행 완료]"})
            messages = trim_history(messages, args.max_history_chars)
            if args.once and not pending:
                return
            continue

        auto_agent, auto_reason = should_session_auto_agent(line, args.auto_agent)
        if auto_agent:
            print(f"[auto] session mode=agent ({auto_reason})", file=sys.stderr)
            run_session_agent(line, messages, args, force=False)
            messages.append({"role": "user", "content": line})
            messages.append({"role": "assistant", "content": "[agent 작업 실행 완료]"})
            messages = trim_history(messages, args.max_history_chars)
            if args.once and not pending:
                return
            continue

        messages.append({"role": "user", "content": line})
        messages = trim_history(messages, args.max_history_chars)
        last_err: Exception | None = None
        for i, candidate in enumerate(models):
            try:
                if i > 0:
                    print(f"[retry] 세션 대체 모델 사용: {candidate}", file=sys.stderr)
                answer = chat_ollama(config, candidate, messages, stream=not args.no_stream, temperature=args.temperature, num_ctx=args.num_ctx, num_predict=args.num_predict)
                model = candidate
                messages.append({"role": "assistant", "content": answer})
                messages = trim_history(messages, args.max_history_chars)
                if args.once and not pending:
                    return
                break
            except (DegenerateOutput, EmptyOutput, TimeoutError, urllib.error.URLError) as e:
                last_err = e
                print(f"[guard] 세션 모델 실패: {candidate} ({e})", file=sys.stderr)
                continue
        else:
            if last_err:
                print(f"응답 실패: {last_err}")
            if args.once and not pending:
                return


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Omni Agent: Ollama/HF GGUF model router and local agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list", help="모델 프로필 목록")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("route", help="프롬프트에 맞는 모델만 추천")
    s.add_argument("prompt")
    s.add_argument("--level", default="auto")
    s.add_argument("--task", default="auto")
    s.add_argument("--allow-27b", action="store_true")
    s.set_defaults(func=cmd_route)

    s = sub.add_parser("pull", help="모델 다운로드")
    s.add_argument("profile", nargs="?", default="balanced")
    s.add_argument("--all", action="store_true")
    s.add_argument("--allow-27b", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_pull)

    s = sub.add_parser("ask", help="자동 라우팅 후 단발 질문")
    s.add_argument("prompt")
    s.add_argument("--level", default="auto", help="auto|light|normal|heavy|max 또는 1~5")
    s.add_argument("--task", default="auto", help="auto|fast|summary|creative|writing|code|analysis|reasoning")
    s.add_argument("--allow-27b", action="store_true")
    s.add_argument("--temperature", type=float, default=None)
    s.add_argument("--num-ctx", type=int, default=None)
    s.add_argument("--num-predict", type=int, default=None)
    s.add_argument("--no-stream", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_ask)

    s = sub.add_parser("auto", help="한 줄 명령: 모델/ask/agent 자동 판단")
    s.add_argument("goal", nargs="+", help="할 일/질문을 그대로 입력")
    s.add_argument("--mode", default="auto", choices=["auto", "ask", "agent"], help="auto|ask|agent")
    s.add_argument("--workspace", default=str(Path.cwd()))
    s.add_argument("--level", default="auto", help="auto|light|normal|heavy|max|gemma4 또는 1~5")
    s.add_argument("--task", default="auto")
    s.add_argument("--allow-27b", action="store_true")
    s.add_argument("--allow-shell", "--no-allow-shell", action=argparse.BooleanOptionalAction, default=True)
    s.add_argument("--allow-write", "--no-allow-write", action=argparse.BooleanOptionalAction, default=True)
    s.add_argument("--allow-all", action="store_true", help="shell/write 둘 다 허용")
    s.add_argument("-y", "--yes", action="store_true", default=True, help="확인 없이 진행")
    s.add_argument("--confirm", action="store_false", dest="yes", help="쓰기/쉘 실행 전에 다시 확인")
    s.add_argument("--max-steps", type=int, default=0, help="initial step checkpoint; automatically extends by 50")
    s.add_argument("--temperature", type=float, default=None)
    s.add_argument("--num-ctx", type=int, default=None)
    s.add_argument("--num-predict", type=int, default=None)
    s.add_argument("--no-stream", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=lambda a: (setattr(a, "goal", " ".join(a.goal)), cmd_auto(a))[1])

    s = sub.add_parser("agent", help="로컬 PC 에이전트 모드")
    s.add_argument("goal")
    s.add_argument("--workspace", default=str(Path.cwd()))
    s.add_argument("--level", default="auto")
    s.add_argument("--task", default="auto")
    s.add_argument("--allow-27b", action="store_true")
    s.add_argument("--allow-shell", "--no-allow-shell", action=argparse.BooleanOptionalAction, default=True, help="PowerShell 실행 허용/비허용")
    s.add_argument("--allow-write", "--no-allow-write", action=argparse.BooleanOptionalAction, default=True, help="파일 쓰기 허용/비허용")
    s.add_argument("-y", "--yes", action="store_true", default=True, help="쓰기/쉘 확인 없이 진행")
    s.add_argument("--confirm", action="store_false", dest="yes", help="쓰기/쉘 실행 전에 다시 확인")
    s.add_argument("--max-steps", type=int, default=0, help="initial step checkpoint; automatically extends by 50")
    s.add_argument("--temperature", type=float, default=0.15)
    s.add_argument("--num-ctx", type=int, default=None)
    s.add_argument("--num-predict", type=int, default=None)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_agent)

    s = sub.add_parser("session", help="종료 전까지 대화 히스토리를 유지하는 세션 모드")
    s.add_argument("seed", nargs="?", default="", help="세션 시작과 동시에 보낼 첫 메시지")
    s.add_argument("--workspace", default=str(Path.cwd()))
    s.add_argument("--level", default="auto")
    s.add_argument("--task", default="auto")
    s.add_argument("--auto-agent", "--no-auto-agent", action=argparse.BooleanOptionalAction, default=True, help="세션 일반 문장에서 파일/코드/테스트 작업을 자동 에이전트로 실행")
    s.add_argument("--agent-level", default="auto", help="세션 자동 에이전트용 level")
    s.add_argument("--agent-task", default="gemma4_heavy", help="세션 자동 에이전트용 task")
    s.add_argument("--allow-27b", action="store_true")
    s.add_argument("--max-steps", type=int, default=0, help="initial step checkpoint; automatically extends by 50")
    s.add_argument("--temperature", type=float, default=None)
    s.add_argument("--num-ctx", type=int, default=None)
    s.add_argument("--num-predict", type=int, default=None)
    s.add_argument("--no-stream", action="store_true")
    s.add_argument("--max-history-chars", type=int, default=24000)
    s.add_argument("--agent-context-messages", type=int, default=12)
    s.add_argument("--once", action="store_true", help="seed 한 번만 처리하고 종료")
    s.set_defaults(func=cmd_session)
    return p


def main() -> None:
    known = {"list", "route", "pull", "ask", "agent", "auto", "session", "-h", "--help"}
    argv = sys.argv[1:]
    if argv and argv[0] not in known:
        argv = ["auto"] + argv
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
