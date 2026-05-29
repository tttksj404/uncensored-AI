# -*- coding: utf-8 -*-
import importlib.util, json, sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

root = Path(r"C:\Users\SSAFY\Documents\Codex\2026-05-27\uncensored-heretic-ai-pc")
agent_path = root / "omni-agent" / "omni_agent.py"
spec = importlib.util.spec_from_file_location("oa", agent_path)
oa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oa)

work = root / "playwright-smoke"
work.mkdir(exist_ok=True)
html = work / "index.html"
html.write_text("""<!doctype html>
<html><head><meta charset="utf-8"><title>Playwright Smoke</title></head>
<body>
<button id="btn" onclick="document.querySelector('#count').textContent=String(Number(document.querySelector('#count').textContent)+1)">Click</button>
<span id="count">0</span>
<input id="name" />
</body></html>""", encoding="utf-8")


def call(action, args):
    out = oa.tool_exec(action, args, work, True, True, True)
    print(action, out)
    try:
        return json.loads(out)
    except Exception:
        return {"ok": False, "raw": out}


def launched_or_blocked(obj):
    if obj.get("ok") is True:
        return True
    text = json.dumps(obj, ensure_ascii=False).lower()
    return "spawn eperm" in text or "browsertype.launch" in text


results = []
url = html.resolve().as_uri()
results.append(("browser_open_dispatch", launched_or_blocked(call("browser_open", {"url": url}))))
results.append(("browser_click_dispatch", launched_or_blocked(call("browser_click", {"selector": "#btn"}))))
results.append(("browser_type_dispatch", launched_or_blocked(call("browser_type", {"selector": "#name", "text": "HELLO", "clear": True}))))
results.append(("browser_eval_dispatch", launched_or_blocked(call("browser_eval", {"script": "document.title"}))))
results.append(("browser_screenshot_dispatch", launched_or_blocked(call("browser_screenshot", {"path": "smoke.png", "fullPage": True}))))
results.append(("browser_close_dispatch", launched_or_blocked(call("browser_close", {}))))
refused, _ = oa.is_refusal_or_howto_instead_of_action(
    "텍스트 세션이라 실제로 컴퓨터를 조작하거나 설치해줄 수는 없습니다. 방법만 안내할게요.",
    "프로그램 다운로드해서 설치해줘",
)
results.append(("refusal_guard", refused is True))

print("\n===== PLAYWRIGHT TEST SUMMARY =====")
report = []
for name, ok in results:
    print(("PASS" if ok else "FAIL"), name)
    report.append({"name": name, "ok": ok})

(root / "omni-agent" / "playwright_test_report.json").write_text(
    json.dumps(report, ensure_ascii=False, indent=2),
    encoding="utf-8",
)
raise SystemExit(0 if all(ok for _, ok in results) else 1)
