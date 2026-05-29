using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Collections.Generic;

class LocalAILauncher
{
    static readonly string HardRoot = @"C:\Users\SSAFY\Documents\Codex\2026-05-27\uncensored-heretic-ai-pc";

    static string Quote(string s)
    {
        if (s == null) return "\"\"";
        return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    static string FindScript()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string p0 = Path.Combine(baseDir, "ai.ps1");
        if (File.Exists(p0)) return p0;
        string p1 = Path.Combine(baseDir, "omni-agent", "omni_agent.py");
        if (File.Exists(p1))
        {
            string ps = Path.Combine(baseDir, "omni-agent", "omni.ps1");
            if (File.Exists(ps)) return ps;
        }
        string p2 = Path.Combine(baseDir, "omni_agent.py");
        if (File.Exists(p2))
        {
            string ps = Path.Combine(baseDir, "omni.ps1");
            if (File.Exists(ps)) return ps;
        }
        string p2b = Path.Combine(HardRoot, "ai.ps1");
        if (File.Exists(p2b)) return p2b;
        string p3 = Path.Combine(HardRoot, "omni-agent", "omni_agent.py");
        if (File.Exists(p3))
        {
            string ps = Path.Combine(HardRoot, "omni-agent", "omni.ps1");
            if (File.Exists(ps)) return ps;
        }
        throw new FileNotFoundException("ai.ps1/omni.ps1 not found. Expected under project folder.");
    }

    static int RunPython(List<string> args)
    {
        string script = FindScript();
        string argLine = "-ExecutionPolicy Bypass -File " + Quote(script);
        foreach (string a in args) argLine += " " + Quote(a);

        var psi = new ProcessStartInfo();
        psi.FileName = "powershell.exe";
        psi.Arguments = argLine;
        psi.WorkingDirectory = HardRoot;
        psi.UseShellExecute = false;
        psi.RedirectStandardInput = false;
        psi.RedirectStandardOutput = false;
        psi.RedirectStandardError = false;
        var p = Process.Start(psi);
        p.WaitForExit();
        return p.ExitCode;
    }

    static void Help()
    {
        Console.WriteLine("\nAI.exe 로컬 만능 호출기");
        Console.WriteLine("그냥 할 일을 입력하면 모델/ask/agent 모드를 자동 판단합니다. /agent 필요 없음.\n");
        Console.WriteLine("예시:");
        Console.WriteLine("  현재 폴더 구조 분석해줘");
        Console.WriteLine("  README 수정해줘");
        Console.WriteLine("  테스트 실행하고 실패 고쳐줘");
        Console.WriteLine("  Gemma4로 긴 한국어 대화 처리해줘");
        Console.WriteLine("\n특수 명령:");
        Console.WriteLine("  /help          도움말");
        Console.WriteLine("  /list          모델 목록");
        Console.WriteLine("  /agent 작업    강제 agent 모드");
        Console.WriteLine("  /ask 질문      강제 ask 모드");
        Console.WriteLine("  /exit          종료\n");
    }

    static int Interactive()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;
        Console.Title = "Local AI Omni Agent";
        Console.WriteLine("Local AI Omni Agent");
        Console.WriteLine("할 일을 그대로 입력하세요. 모델/에이전트 모드는 자동 판단됩니다. (/help 도움말, /exit 종료)\n");
        while (true)
        {
            Console.Write("AI> ");
            string line = Console.ReadLine();
            if (line == null) return 0;
            line = line.Trim();
            if (line.Length == 0) continue;
            string lower = line.ToLowerInvariant();
            if (lower == "/exit" || lower == "exit" || lower == "quit" || lower == "q") return 0;
            if (lower == "/help" || lower == "help") { Help(); continue; }
            if (lower == "/list" || lower == "list") { RunPython(new List<string>{"list"}); continue; }

            var pyArgs = new List<string>();
            if (lower.StartsWith("/agent "))
            {
                pyArgs.Add("auto");
                pyArgs.Add(line.Substring(7).Trim());
                pyArgs.Add("--mode");
                pyArgs.Add("agent");
            }
            else if (lower.StartsWith("/ask "))
            {
                pyArgs.Add("auto");
                pyArgs.Add(line.Substring(5).Trim());
                pyArgs.Add("--mode");
                pyArgs.Add("ask");
            }
            else
            {
                pyArgs.Add("session"); pyArgs.Add(line);
            }
            Console.WriteLine();
            RunPython(pyArgs);
            Console.WriteLine();
        }
    }

    static int Main(string[] args)
    {
        try
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;
            if (args.Length == 0) return RunPython(new List<string>{"session"});
            var known = new HashSet<string>{"list","route","pull","ask","agent","auto","session","-h","--help"};
            if (!known.Contains(args[0]))
            {
                // One-shot command line input must go through auto so options like
                // --dry-run/--workspace/--max-steps are honored instead of being
                // swallowed as session text.
                var autoArgs = new List<string>{"auto"};
                autoArgs.AddRange(args);
                return RunPython(autoArgs);
            }
            return RunPython(new List<string>(args));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("AI.exe error: " + ex.Message);
            Console.Error.WriteLine("Enter 키를 누르면 종료합니다.");
            Console.ReadLine();
            return 1;
        }
    }
}


