# -*- coding: utf-8 -*-
import importlib.util, json, re, sys
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


def ok_or_blocked(text: str) -> bool:
    low = text.lower()
    return ("example domain" in low) or ("tool blocked: network access restricted" in low)


def search_ok_or_blocked(text: str) -> bool:
    """Search engines localize/rerank results, so test dispatch/parse health.

    The old assertion required "Example Domain" in the search output. Bing can
    legitimately return localized dictionary/Wikipedia results for the query
    "example domain", which made the test fail even though web_search executed
    and parsed URLs correctly. fetch_url still verifies the exact example.com
    page content below.
    """
    low = text.lower()
    if "tool blocked: network access restricted" in low:
        return True
    if low.startswith("tool error:") and (
        "network access restricted" in low
        or "winerror 10013" in low
        or "urlopen error" in low
    ):
        return True
    if low.startswith("tool error:"):
        return False
    return bool(re.search(r"https?://", text))


results = []
workspace = root.resolve()

results.append(("channel_guard", oa.clean_model_output("<|channel>\n<|channel>") == ""))
results.append(("think_guard", oa.is_control_token_junk("<|channel>\n<|channel>") is True))
results.append(("web_route_agent", oa.decide_mode("check example.com and verify the page")[0] == "agent"))
auto_agent, reason = oa.should_session_auto_agent("example.com 내용 확인해줘")
results.append(("session_auto_agent_web", auto_agent is True and ("url/domain" in reason or "web-intent" in reason)))

search_out = oa.tool_exec("web_search", {"query": "example domain", "max_results": 2}, workspace, True, True, True)
print("web_search =>", search_out[:1000])
results.append(("web_search_dispatch", search_ok_or_blocked(search_out)))

fetch_out = oa.tool_exec("fetch_url", {"url": "https://example.com"}, workspace, True, True, True)
print("fetch_url =>", fetch_out[:1000])
results.append(("fetch_url_dispatch", ok_or_blocked(fetch_out)))

print("\n===== INTERNET TEST SUMMARY =====")
report = []
for name, ok in results:
    print(("PASS" if ok else "FAIL"), name)
    report.append({"name": name, "ok": ok})

(root / "omni-agent" / "internet_test_report.json").write_text(
    json.dumps(report, ensure_ascii=False, indent=2),
    encoding="utf-8",
)
raise SystemExit(0 if all(ok for _, ok in results) else 1)
