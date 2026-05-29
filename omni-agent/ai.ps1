param(
  [Parameter(ValueFromRemainingArguments=$true)]
  [string[]]$Args
)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
python "$ScriptDir\omni_agent.py" @Args
