# -*- coding: utf-8 -*-
import os, subprocess, sys, shutil, json
from pathlib import Path
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass
root=Path(r'C:\Users\SSAFY\Documents\Codex\2026-05-27\uncensored-heretic-ai-pc')
agent=root/'omni-agent'/'omni_agent.py'
exe=root/'AI.exe'
env=os.environ.copy(); env['PYTHONUTF8']='1'; env['PYTHONIOENCODING']='utf-8'; env['OLLAMA_HOST']='http://[::1]:11435'

def run(name,args,inp,timeout=900):
    print('\n===== '+name+' =====')
    p=subprocess.run(args,cwd=root,input=inp,text=True,encoding='utf-8',errors='replace',stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout,env=env)
    print(p.stdout[:4000]); print('EXIT',p.returncode)
    return p.stdout,p.returncode

results=[]
out,code=run('python-session-memory',[sys.executable,str(agent),'session','--no-stream','--num-ctx','4096','--num-predict','160'], 'My codename is BLUE-RAVEN. Remember it.\nWhat is my codename? Answer only the codename.\n/exit\n')
results.append(('python-session-memory', code==0 and 'BLUE-RAVEN' in out.split('AI>')[-2]))

out,code=run('exe-session-memory',[str(exe)], 'My codename is RED-FOX. Remember it.\nWhat is my codename? Answer only the codename.\n/exit\n')
results.append(('exe-session-memory', code==0 and 'RED-FOX' in out))

out,code=run('session-clear',[sys.executable,str(agent),'session','--no-stream','--num-ctx','4096','--num-predict','160'], 'My codename is GREEN-WOLF. Remember it.\n/clear\nWhat was my codename?\n/exit\n')
# after clear, it should not confidently answer GREEN-WOLF in final answer; allow mention from echoed prior line in transcript, check last answer segment
last_answer=out.split('AI>')[-2] if out.count('AI>')>=2 else out
results.append(('session-clear', code==0 and 'GREEN-WOLF' not in last_answer))

work=root/'session-agent-memory-test'
if work.exists(): shutil.rmtree(work)
work.mkdir()
out,code=run('session-agent-context',[sys.executable,str(agent),'session','--workspace',str(work),'--no-stream','--num-ctx','4096','--num-predict','256'], 'The project codeword is SILVER-OWL. Remember it.\n/agent create note.txt containing the project codeword only\n/exit\n', timeout=1200)
file_ok=(work/'note.txt').exists() and 'SILVER-OWL' in (work/'note.txt').read_text(encoding='utf-8',errors='replace')
print('file_ok',file_ok, 'content', (work/'note.txt').read_text(encoding='utf-8',errors='replace') if (work/'note.txt').exists() else '<missing>')
results.append(('session-agent-context', code==0 and file_ok))

direct=root/'session-direct-agent-test'
if direct.exists(): shutil.rmtree(direct)
direct.mkdir()
out,code=run('session-direct-auto-agent-create',[sys.executable,str(agent),'session','--workspace',str(direct),'--no-stream','--num-ctx','4096','--num-predict','256','--once'], 'create direct_auto.txt containing DIRECT-AUTO only\n', timeout=1200)
direct_ok=(direct/'direct_auto.txt').exists() and 'DIRECT-AUTO' in (direct/'direct_auto.txt').read_text(encoding='utf-8',errors='replace')
print('direct_ok',direct_ok, 'content', (direct/'direct_auto.txt').read_text(encoding='utf-8',errors='replace') if (direct/'direct_auto.txt').exists() else '<missing>')
results.append(('session-direct-auto-agent-create', code==0 and direct_ok))

codework=root/'session-direct-code-edit-test'
if codework.exists(): shutil.rmtree(codework)
codework.mkdir()
(codework/'sample.py').write_text("VALUE = 'OLD'\nprint(VALUE)\n",encoding='utf-8')
out,code=run('session-direct-auto-agent-code-edit',[sys.executable,str(agent),'session','--workspace',str(codework),'--no-stream','--num-ctx','4096','--num-predict','512','--once'], 'sample.py 코드 파일을 직접 수정해서 OLD를 NEW로 바꿔놓고 완료 보고해\n', timeout=1200)
edited=(codework/'sample.py').read_text(encoding='utf-8',errors='replace')
edit_ok='NEW' in edited and 'OLD' not in edited
print('edit_ok',edit_ok, 'content', edited)
results.append(('session-direct-auto-agent-code-edit', code==0 and edit_ok))

print('\n===== SESSION TEST SUMMARY =====')
for name,ok in results: print(('PASS' if ok else 'FAIL'), name)
Path(root/'omni-agent'/'session_test_report.json').write_text(json.dumps([{'name':n,'ok':ok} for n,ok in results],indent=2),encoding='utf-8')
raise SystemExit(0 if all(ok for _,ok in results) else 1)
