# -*- coding: utf-8 -*-
import json, os, re, shutil, subprocess, sys, time, urllib.request
from pathlib import Path
from collections import Counter

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

ROOT = Path(r'C:\Users\SSAFY\Documents\Codex\2026-05-27\uncensored-heretic-ai-pc')
PY = sys.executable
AGENT = ROOT / 'omni-agent' / 'omni_agent.py'
EXE = ROOT / 'AI.exe'
HOST = 'http://[::1]:11435'
STRICT_WORDS = ['uncensored','heretic','abliterated']

def degenerate(text):
    compact=re.sub(r'\s+',' ', text or '').strip().lower()
    if re.search(r'(.)(\1){24,}', compact): return True, 'char_repeat'
    words=re.findall(r'[A-Za-z가-힣0-9_]+', compact)
    if len(words)>=80:
        w,c=Counter(words).most_common(1)[0]
        if c/max(1,len(words))>=0.28 and c>=30: return True, f'word_repeat:{w}:{c}'
        for n in (2,3,4):
            grams=[tuple(words[i:i+n]) for i in range(len(words)-n+1)]
            if grams:
                g,gc=Counter(grams).most_common(1)[0]
                if gc>=18 and (gc*n)/max(1,len(words))>=0.22: return True, 'phrase_repeat:'+' '.join(g)
    if len(words)>=160 and len(set(words))/len(words)<0.12: return True, 'low_unique_ratio'
    return False,''

def run(name,args,timeout=120,stdin=None,allow_empty=False,check_repeat=True):
    env=os.environ.copy(); env['PYTHONUTF8']='1'; env['PYTHONIOENCODING']='utf-8'; env['OLLAMA_HOST']=HOST
    print(f'\n===== {name} =====')
    t=time.time()
    try:
        p=subprocess.run(args,cwd=ROOT,input=stdin,text=True,encoding='utf-8',errors='replace',stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout,env=env)
        dt=round(time.time()-t,1); out=p.stdout or ''
        print(out[:3000]); print(f'EXIT={p.returncode} TIME={dt}s LEN={len(out)}')
        ok=p.returncode==0
        reason=''
        if not allow_empty and len(out.strip())==0:
            ok=False; reason='empty_output'
        if check_repeat:
            bad,why=degenerate(out)
            if bad: ok=False; reason=why
        return {'name':name,'ok':ok,'code':p.returncode,'time':dt,'reason':reason,'out':out[:800]}
    except subprocess.TimeoutExpired as e:
        out=e.stdout if isinstance(e.stdout,str) else ''
        print((out or '')[:3000]); print(f'TIMEOUT {timeout}s')
        return {'name':name,'ok':False,'code':'timeout','time':timeout,'reason':'timeout','out':(out or '')[:800]}

results=[]
# API + strict inventory
print('===== api/inventory =====')
try:
    data=json.load(urllib.request.urlopen(HOST+'/api/tags',timeout=10))
    names=[m['name'] for m in data.get('models',[])]
    print('API OK models',len(names)); print('\n'.join(names))
    results.append({'name':'api','ok':True,'code':0,'time':0,'reason':'','out':''})
except Exception as e:
    print('API FAIL',e); results.append({'name':'api','ok':False,'code':1,'time':0,'reason':repr(e),'out':''})

cfg=json.load(open(ROOT/'omni-agent'/'models.json',encoding='utf-8-sig'))
profile_bad=[]
for k,v in cfg['profiles'].items():
    model=v['model'].lower()
    if not any(w in model for w in STRICT_WORDS):
        profile_bad.append((k,v['model']))
print('strict_profile_bad',profile_bad)
results.append({'name':'strict-router-profiles','ok':len(profile_bad)==0,'code':0 if not profile_bad else 1,'time':0,'reason':str(profile_bad),'out':''})

# Dry routing and execution modes
basic_cmds=[
 ('list',[PY,str(AGENT),'list'],60,True),
 ('route-fast',[PY,str(AGENT),'route','간단히 요약해줘'],60,False),
 ('route-code',[PY,str(AGENT),'route','코드 버그 분석하고 고쳐줘'],60,False),
 ('route-heavy',[PY,str(AGENT),'route','복잡한 아키텍처 정확히 분석해줘'],60,False),
 ('auto-ask-dry',[PY,str(AGENT),'간단히 요약해줘','--dry-run'],60,True),
 ('auto-agent-dry',[PY,str(AGENT),'현재 폴더 구조 분석해줘','--dry-run'],60,True),
 ('exe-dry',[str(EXE),'Gemma4로 처리','--dry-run'],240,True),
 ('interactive-exit',[str(EXE)],30,True),
]
for name,args,to,allow_empty in basic_cmds:
    results.append(run(name,args,to,stdin='/exit\n' if name=='interactive-exit' else None,allow_empty=allow_empty,check_repeat=False))

# Actual answer tests - short/medium/Korean/code/long/repetition-prone
actual_cmds=[
 ('actual-short',[PY,str(AGENT),'ask','2+2 답만 숫자로','--task','summary','--no-stream','--num-ctx','1024','--num-predict','32'],120),
 ('actual-korean',[PY,str(AGENT),'ask','로컬 AI 라우터를 한국어로 세 문장 요약','--task','summary','--no-stream','--num-ctx','2048','--num-predict','160'],160),
 ('actual-code',[PY,str(AGENT),'ask','JS에서 회색 배경만 가진 div를 찾아 class gray-item을 붙이는 짧은 예시 코드','--task','code','--no-stream','--num-ctx','2048','--num-predict','220'],180),
 ('actual-long',[PY,str(AGENT),'ask','CSS와 JS로 선택된 항목만 회색 처리하는 예시를 설명 포함 500자 이내로 작성. 같은 단어 반복 금지.','--task','code','--no-stream','--num-ctx','2048','--num-predict','360'],180),
 ('actual-repeat-trap',[PY,str(AGENT),'ask','다음 단어를 반복하지 말고, 반복 출력 문제를 방지하는 방법 5가지만 써: own same 만만만','--task','summary','--no-stream','--num-ctx','2048','--num-predict','260'],180),
 ('actual-exe',[str(EXE),'로컬 모델 라우터를 한 문장으로 설명','--task','summary','--no-stream','--num-ctx','1024','--num-predict','80'],160),
]
for name,args,to in actual_cmds:
    results.append(run(name,args,to,allow_empty=False,check_repeat=True))

# Agent tests with strict heretic model
smoke=ROOT/'stress-agent-workspace'
if smoke.exists(): shutil.rmtree(smoke)
smoke.mkdir()
results.append(run('agent-write',[PY,str(AGENT),'agent','result.txt 파일을 만들고 내용은 OK 한 줄만 쓰고 final로 완료 보고','--workspace',str(smoke),'--task','gemma4_heavy','--max-steps','6','--num-ctx','2048','--num-predict','512'],300,allow_empty=True,check_repeat=True))
file_ok=(smoke/'result.txt').exists() and (smoke/'result.txt').read_text(encoding='utf-8').strip()=='OK'
print('\n===== agent-file-check =====')
print('file_ok',file_ok)
results.append({'name':'agent-file-check','ok':file_ok,'code':0 if file_ok else 1,'time':0,'reason':'' if file_ok else 'missing/wrong file','out':''})

# Timeout/guard simulated direct function check via Python import
sim='''import importlib.util, pathlib\np=pathlib.Path(r"C:\\Users\\SSAFY\\Documents\\Codex\\2026-05-27\\uncensored-heretic-ai-pc\\omni-agent\\omni_agent.py")\ns=importlib.util.spec_from_file_location("oa",p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\ntext="own "*200\nprint(m.is_degenerate_output(text))\nraise SystemExit(0 if m.is_degenerate_output(text)[0] else 1)\n'''
results.append(run('guard-simulated',[PY,'-c',sim],60,allow_empty=False,check_repeat=False))

print('\n===== STRESS SUMMARY =====')
for r in results:
    print(f"{'PASS' if r['ok'] else 'FAIL'} {r['name']} code={r['code']} time={r['time']} reason={r['reason']}")
fail=[r for r in results if not r['ok']]
# save JSON report
report=ROOT/'omni-agent'/'stress_report.json'
report.write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
print('REPORT',report)
if fail: sys.exit(1)
