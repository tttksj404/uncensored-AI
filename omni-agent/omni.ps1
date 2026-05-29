param(
  [Parameter(ValueFromRemainingArguments=$true)]
  [string[]]$Args
)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
function Test-PythonCandidate($candidate) {
  if (-not $candidate -or -not (Test-Path $candidate)) { return $false }
  try {
    $out = & $candidate --version 2>&1
    return ($LASTEXITCODE -eq 0 -and ($out -match 'Python'))
  } catch {
    return $false
  }
}
function Find-Python {
  $candidates = @()
  if ($env:AI_PYTHON) { $candidates += $env:AI_PYTHON }
  $cmd = Get-Command python -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.Source) { $candidates += $cmd.Source }
  $cmdPy = Get-Command py -ErrorAction SilentlyContinue
  if ($cmdPy -and $cmdPy.Source) { $candidates += $cmdPy.Source }
  $candidates += @(
    'C:\SAI\SAI.Application\Python\venv\python.exe',
    'C:\mingw64\lib\python3.9\venv\scripts\nt\python.exe'
  )
  foreach ($candidate in $candidates | Select-Object -Unique) {
    if (Test-PythonCandidate $candidate) { return $candidate }
  }
  throw 'python executable not found'
}
& (Find-Python) "$ScriptDir\omni_agent.py" @Args
