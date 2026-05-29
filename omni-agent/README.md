# Omni Agent — 로컬 AI 만능 호출기

Hugging Face GGUF 모델을 Ollama로 불러와서, 사용자가 준 업무강도/작업유형에 맞게 자동 선택하는 로컬 호출기입니다.

## 현재 PC용 기본 라우팅

| 강도 | 프로필 | 모델 |
|---|---|---|
| light / 1 | fast | `hf.co/mradermacher/Qwen3-4B-2507-Thinking-heretic-abliterated-uncensored-GGUF:Q4_K_M` |
| normal / 2 | balanced | `hf.co/llmfan46/Qwen3.5-9B-ultra-uncensored-heretic-v2-GGUF:Q4_K_M` |
| creative | creative | `hf.co/llmfan46/gemma-4-E4B-it-ultra-uncensored-heretic-GGUF:Q4_K_M` |
| heavy / 3~4 | heavy | `hf.co/KevinJK51/Qwen3.6-12B-IQ-Ultra-Heretic-Uncensored-Thinking-V2-Hightop-GGUF:Q4_K_M` |
| max / 5 | max27b | `hf.co/llmfan46/Qwen3.6-27B-uncensored-heretic-v2-GGUF:Q3_K_M` (`--allow-27b` 필요) |

## 빠른 사용법

PowerShell:

```powershell
cd "C:\Users\SSAFY\Documents\Codex\2026-05-27\uncensored-heretic-ai-pc\omni-agent"
.\omni.ps1 list
.\omni.ps1 route "이 코드 버그 분석해줘"
.\omni.ps1 ask "윈도우에서 파이썬 가상환경 만드는 법 짧게" --level light
.\omni.ps1 ask "복잡한 프로그램 구조 설계해줘" --level heavy --task analysis
```

처음 실행 시 해당 모델이 없으면 자동으로 `ollama pull` 합니다.

## 모델 미리 받기

추천 3개만 먼저:

```powershell
.\omni.ps1 pull fast
.\omni.ps1 pull balanced
.\omni.ps1 pull heavy
```

전체 받기(27B 제외):

```powershell
.\omni.ps1 pull --all
```

27B까지:

```powershell
.\omni.ps1 pull --all --allow-27b
```

## 에이전트 모드

읽기/검색 위주:

```powershell
.\omni.ps1 agent "현재 폴더 구조 보고 개선 포인트 알려줘" --workspace "C:\path\to\project"
```

파일 수정 허용:

```powershell
.\omni.ps1 agent "README를 새로 정리해줘" --workspace "C:\path\to\project" --allow-write
```

쉘 실행까지 허용:

```powershell
.\omni.ps1 agent "테스트 실행하고 실패 원인 고쳐줘" --workspace "C:\path\to\project" --allow-shell --allow-write
```

완전 자동 진행:

```powershell
.\omni.ps1 agent "테스트 실패 고치고 결과 요약해줘" --workspace "C:\path\to\project" --allow-shell --allow-write -y --level heavy --max-steps 12
```

## 자동 선택 기준

- `--level light`: 빠른 4B
- `--level normal`: 9B Heretic balanced
- `--level heavy`: 12B Thinking
- `--level max --allow-27b`: 27B 느린 최고품질 후보
- `--task creative`: Gemma Heretic creative
- `--task code`: 9B balanced
- `--task analysis`: 12B heavy
- `auto`: 프롬프트 키워드와 길이를 보고 자동 선택

## 설정 변경

`models.json`에서 프로필, 모델명, temperature, context를 수정하면 됩니다.

예: `balanced`를 Q5로 바꾸려면:

```json
"model": "hf.co/llmfan46/Qwen3.5-9B-ultra-uncensored-heretic-v2-GGUF:Q5_K_M"
```


## 로컬에 이미 있는 Gemma4 통합

현재 Ollama에 이미 있는 모델도 라우터에 합쳤습니다.

| 프로필 | 모델 | 용도 |
|---|---|---|
| `gemma4_local` | `gemma4:latest` | 이미 설치된 9.6GB Gemma4, 창작/긴 대화/한국어 대화 |
| `gemma4_uncensored_local` | `hf.co/HauhauCS/Gemma-4-E4B-Uncensored-HauhauCS-Aggressive:Q4_K_M` | 이미 설치된 6.3GB Gemma4 uncensored, 빠른 창작/대화 |

직접 호출:

```powershell
.\omni.ps1 ask "Gemma4로 긴 대화 테스트" --task gemma4
.\omni.ps1 ask "Gemma4 uncensored로 창작 초안" --task gemma4_uncensored
```

강도 alias:

```powershell
.\omni.ps1 ask "로컬 gemma4 써서 처리해줘" --level gemma4
```

## 제일 간단한 한 줄 호출

이제 `ask`, `agent`, `task`, `level`을 몰라도 됩니다. 그냥 할 말을 그대로 넣으면 호출기가 판단합니다.

프로젝트 루트에서:

```powershell
.\ai.ps1 "이 폴더 구조 분석하고 개선점 알려줘"
.\ai.ps1 "Gemma4로 긴 한국어 대화 처리해줘"
.\ai.ps1 "README 정리하고 부족한 내용 채워줘" --allow-write
.\ai.ps1 "테스트 실행하고 실패 고쳐줘" --allow-all -y --level heavy
```

`omni-agent` 폴더 안에서는:

```powershell
.\ai.ps1 "간단히 요약해줘"
```

자동 판단 내용:

- 단순 질문이면 `ask` 모드
- 파일/폴더/코드/테스트/수정 작업이면 `agent` 모드
- `gemma4`라고 쓰면 로컬 `gemma4:latest`
- `gemma4 uncensored`라고 쓰면 로컬 Gemma4 uncensored
- 복잡/정확/분석/설계면 heavy 계열
- 짧게/간단/요약이면 fast 계열

## 권한 기본값

요청대로 에이전트 권한 기본값을 전부 허용으로 바꿨습니다.

기본값:

- 파일 읽기: 허용
- 파일 쓰기/수정: 허용
- PowerShell 실행: 허용
- 실행 전 확인 질문: 안 함

따라서 이제 아래처럼 옵션 없이도 수정/실행 작업을 진행합니다.

```powershell
.\ai.ps1 "README 수정해줘"
.\ai.ps1 "테스트 실행하고 실패 고쳐줘"
```

임시로 안전 모드처럼 쓰고 싶으면:

```powershell
.\ai.ps1 "README 수정해줘" --confirm
.\ai.ps1 "분석만 해줘" --no-allow-write --no-allow-shell
```

## Persistent Session Mode

`AI.exe`를 더블클릭하거나 인자 없이 실행하면 이제 기본으로 `session` 모드가 열립니다.

특징:

- `/exit` 전까지 같은 창 안의 이전 대화를 계속 기억합니다.
- `/clear`를 입력하면 세션 기억을 초기화합니다.
- `/history`로 현재 히스토리 상태를 확인합니다.
- `/agent 작업내용`을 입력하면 이전 대화 컨텍스트를 포함해서 에이전트 작업을 수행합니다.
- 세션 기본 모델은 strict uncensored/heretic 모델인 `Qwen3.5 27B uncensored heretic Q3`입니다.
- 에이전트 작업은 `Gemma4 31B Heretic`을 사용합니다.

검증 완료:

```powershell
python .\omni-agent\session_test.py
```

통과 항목:

- Python session multi-turn memory
- AI.exe session multi-turn memory
- /clear memory reset
- /agent command receiving prior session context and writing a file

## 자동 에이전트 실행

세션 모드에서는 `/agent`를 붙이지 않아도 파일/코드/테스트/빌드/설치/검색/수정 요청을 감지하면 자동으로 에이전트 모드가 실행됩니다.

예:
```text
README.md 고쳐줘
sample.py에서 OLD를 NEW로 바꿔놔
테스트 돌리고 실패 원인 수정해줘
현재 폴더 구조 분석해서 정리해줘
```

일반 질문만 하고 싶으면 `--no-auto-agent`로 세션을 시작하면 됩니다.

## 인터넷/HTML/브라우저 도구

에이전트 모드에서 인터넷 작업도 직접 실행합니다.

사용 가능한 도구:
- `web_search`: DuckDuckGo HTML 검색 결과 조회
- `fetch_url`: URL/HTML 접속 후 텍스트 추출
- `open_url`: 기본 브라우저로 URL 열기

예:
```text
example.com 검색해서 첫 결과 확인해줘
https://example.com 접속해서 HTML 내용 요약해줘
브라우저로 https://example.com 열어줘
```

`<|channel>` 같은 제어 토큰만 출력되는 경우는 빈 출력으로 차단하고 같은 step에서 JSON 재출력을 요구하도록 보정했습니다.

## Playwright 브라우저/마우스 조작

에이전트가 Playwright를 통해 실제 Chromium 브라우저를 열고 마우스/키보드 조작을 수행할 수 있습니다.

추가된 action:
- `browser_open`: URL 또는 `file:///...` 열기
- `browser_click`: CSS selector 또는 x/y 좌표 클릭
- `browser_type`: selector 또는 현재 포커스에 텍스트 입력
- `browser_press`: Enter 등 키 입력
- `browser_screenshot`: 화면 캡처 저장
- `browser_eval`: 페이지 JavaScript 실행으로 실제 상태 검증
- `browser_text`: 페이지 텍스트 읽기
- `browser_close`: 브라우저 닫기

예:
```text
example.com 열어서 More information 링크 클릭해줘
이 페이지에서 검색창에 qwen 입력하고 Enter 눌러줘
현재 페이지 스크린샷 찍고 결과 확인해줘
```

테스트:
```powershell
python .\omni-agent\playwright_test.py
```
