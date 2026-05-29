# -*- coding: utf-8 -*-
import json, os, subprocess, sys, time, urllib.request, shutil
from pathlib import Path
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


ROOT = Path(r'C:\Users\SSAFY\Documents\Codex\2026-05-27\uncensored-heretic-ai-pc')
PY = sys.executable
AGENT = ROOT / 'omni-agent' / 'omni_agent.py'
EXE = ROOT / 'AI.exe'
HOST = 'http://[::1]:11435'

def run(name, args, timeout=90):
    env=os.environ.copy(); env['PYTHONUTF8']='1'; env['PYTHONIOENCODING']='utf-8'; env['OLLAMA_HOST']=HOST
    print(f'\n===== {name} =====')
    t=time.time()
    try:
        p=subprocess.run(args, cwd=ROOT, text=True, encoding='utf-8', errors='replace', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env)
        dt=time.time()-t; out=p.stdout or ''
        print(out[:2200]); print(f'EXIT={p.returncode} TIME={dt:.1f}s')
        return name, p.returncode == 0, p.returncode, round(dt,1), out[:1000]
    except subprocess.TimeoutExpired as e:
        out=(e.stdout or '') if isinstance(e.stdout,str) else ''
        print(out[:2200]); print(f'TIMEOUT after {timeout}s')
        return name, False, 'timeout', timeout, out[:1000]

results=[]
print('===== api-check =====')
try:
    r=urllib.request.urlopen(HOST+'/api/tags',timeout=10); data=json.load(r)
    names=[m['name'] for m in data.get('models',[])]
    print('API OK', HOST, 'models=', len(names)); print('\n'.join(names[:20]))
    results.append(('api-check', True, 0, 0, ''))
except Exception as e:
    print('API FAIL',type(e).__name__,e); results.append(('api-check', False, 1, 0, repr(e)))

cmds = [
 ('list', [PY, str(AGENT), 'list']),
 ('route-fast', [PY, str(AGENT), 'route', '간단히 요약해줘']),
 ('route-code', [PY, str(AGENT), 'route', '코드 버그 분석하고 고쳐줘']),
 ('route-heavy', [PY, str(AGENT), 'route', '복잡한 아키텍처 정확히 분석해줘']),
 ('auto-ask-fast-dry', [PY, str(AGENT), '간단히 요약해줘', '--dry-run']),
 ('auto-ask-gemma4-dry', [PY, str(AGENT), 'Gemma4로 긴 한국어 대화 처리', '--dry-run']),
 ('auto-agent-folder-dry', [PY, str(AGENT), '현재 폴더 구조 분석해줘', '--dry-run']),
 ('auto-agent-write-default-dry', [PY, str(AGENT), 'README 수정해줘', '--dry-run']),
 ('auto-agent-safe-dry', [PY, str(AGENT), 'README 수정해줘', '--dry-run', '--confirm', '--no-allow-write', '--no-allow-shell']),
 ('explicit-agent-dry', [PY, str(AGENT), 'agent', '현재 폴더 목록 봐줘', '--dry-run']),
 ('exe-auto-dry', [str(EXE), '간단히 요약해줘', '--dry-run']),
 ('exe-agent-dry', [str(EXE), '현재 폴더 구조 분석해줘', '--dry-run']),
 ('exe-gemma4-dry', [str(EXE), 'Gemma4로 처리', '--dry-run']),
 ('actual-fast-fallback', [PY, str(AGENT), 'ask', 'Reply OK only', '--task', 'summary', '--no-stream', '--num-ctx', '512', '--num-predict', '8']),
 ('actual-gemma4-local', [PY, str(AGENT), 'ask', 'Reply OK only', '--task', 'gemma4', '--no-stream', '--num-ctx', '512', '--num-predict', '8']),
 ('actual-exe-gemma4', [str(EXE), 'Reply OK only', '--task', 'gemma4', '--no-stream', '--num-ctx', '512', '--num-predict', '8']),
]
for name,args in cmds:
    results.append(run(name,args,timeout=180))

# interactive stdin smoke
print('\n===== interactive-exit =====')
try:
    p=subprocess.run([str(EXE)], cwd=ROOT, input='/exit\n', text=True, encoding='utf-8', errors='replace', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    print((p.stdout or '')[:1200]); print(f'EXIT={p.returncode}')
    results.append(('interactive-exit', p.returncode==0, p.returncode, 0, ''))
except Exception as e:
    print('ERR',type(e).__name__,e); results.append(('interactive-exit', False, 1, 0, repr(e)))


# actual agent write smoke
smoke=ROOT/'agent-smoke-test'
if smoke.exists(): shutil.rmtree(smoke)
smoke.mkdir(parents=True)
results.append(run('actual-agent-write', [PY, str(AGENT), 'agent', 'result.txt 파일을 만들고 내용은 OK 한 줄만 쓰고 final로 완료 보고', '--workspace', str(smoke), '--max-steps', '6', '--num-ctx', '2048', '--num-predict', '512'], timeout=240))
file_ok=(smoke/'result.txt').exists() and (smoke/'result.txt').read_text(encoding='utf-8').strip()=='OK'
print('\n===== agent-file-check =====')
print('file_ok=',file_ok, 'content=', (smoke/'result.txt').read_text(encoding='utf-8') if (smoke/'result.txt').exists() else '<missing>')
results.append(('agent-file-check', file_ok, 0 if file_ok else 1, 0, ''))

print('\n===== FINAL SUMMARY =====')
for name,ok,code,dt,out in results:
    print(f'{"PASS" if ok else "FAIL"} {name} code={code} time={dt}')

bad=[r for r in results if not r[1]]
if bad: sys.exit(1)
