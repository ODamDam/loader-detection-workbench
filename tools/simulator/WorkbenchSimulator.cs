// Workbench benign simulator (M5, ADR-006, ADR-016, ADR-028).
//
// A harmless single executable that reproduces the *shape* of a loader's first
// minutes so the sample execution path (vm run) and the detection pipeline can
// be exercised without malware. It is meant to run only inside the isolated
// analysis VM, which is restored to its clean snapshot afterwards.
//
// Every action stays in the current user's scope and is undone before exit:
// no privilege use, no service or driver, no code download, no file executed
// from disk other than cmd.exe, and the only network activity is a lookup of a
// reserved .invalid name and a connection attempt to TEST-NET-1 (192.0.2.1,
// RFC 5737), which is never routed.
//
// Usage: workbench-simulator.exe [--profile loader-like|benign] [--plan]
//   --plan prints the actions of a profile and performs none of them.
// With no argument the loader-like profile runs (the VM runner passes none).
// Exit code: 0 ok, 2 bad arguments, 3 an action failed (cleanup still ran).
//
// Written for the C# 5 compiler that ships with .NET Framework 4.x.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Win32;

internal static class WorkbenchSimulator
{
    // Fixed marker for YARA rehearsal rules. Never change it in place; add a
    // new version so frozen rules keep matching the binaries they were made for.
    internal const string Marker = "WORKBENCH-SIMULATOR-MARKER-v1";
    internal const string Version = "1";
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValue = "WorkbenchSimulator";
    private const string ConfigKey = @"Software\WorkbenchSimulator";
    private const string InvalidHost = "workbench-sim.example.invalid";
    private const string TestNetAddress = "192.0.2.1";

    private sealed class Step
    {
        public string Name;
        public string Detail;
        public Action Run;
        public Step(string name, string detail, Action run)
        {
            Name = name;
            Detail = detail;
            Run = run;
        }
    }

    private static int Main(string[] args)
    {
        string profile = "loader-like";
        bool planOnly = false;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--plan")
            {
                planOnly = true;
            }
            else if (args[i] == "--profile" && i + 1 < args.Length)
            {
                profile = args[++i];
            }
            else
            {
                Console.Error.WriteLine("usage: workbench-simulator.exe [--profile loader-like|benign] [--plan]");
                return 2;
            }
        }

        string work = Path.Combine(Path.GetTempPath(), "workbench-simulator");
        List<Step> steps = Plan(profile, work);
        if (steps == null)
        {
            Console.Error.WriteLine("unknown profile");
            return 2;
        }

        Console.WriteLine("workbench-simulator " + Version + " profile=" + profile + " marker=" + Marker);
        if (planOnly)
        {
            foreach (Step step in steps)
            {
                Console.WriteLine("plan " + step.Name + ": " + step.Detail);
            }
            return 0;
        }

        List<string> results = new List<string>();
        bool failed = false;
        try
        {
            foreach (Step step in steps)
            {
                string outcome = "ok";
                try
                {
                    step.Run();
                }
                catch (Exception error)
                {
                    // Expected for the network steps on an isolated VM.
                    outcome = "failed:" + error.GetType().Name;
                    if (!step.Name.StartsWith("network"))
                    {
                        failed = true;
                    }
                }
                Console.WriteLine("step " + step.Name + ": " + outcome);
                results.Add("{\"step\":\"" + step.Name + "\",\"outcome\":\"" + outcome + "\"}");
            }
        }
        finally
        {
            Cleanup(work);
        }

        string manifest = "{\"tool\":\"workbench-simulator\",\"version\":\"" + Version
            + "\",\"profile\":\"" + profile + "\",\"steps\":[" + string.Join(",", results.ToArray()) + "]}";
        Console.WriteLine("manifest " + manifest);
        return failed ? 3 : 0;
    }

    private static List<Step> Plan(string profile, string work)
    {
        List<Step> steps = new List<Step>();
        string stage = Path.Combine(work, "stage2.bin");
        string note = Path.Combine(work, "note.txt");
        if (profile == "benign")
        {
            steps.Add(new Step("file-write", "write and read back a text note in %TEMP%", delegate
            {
                Directory.CreateDirectory(work);
                File.WriteAllText(note, "workbench simulator benign profile\r\n");
                File.ReadAllText(note);
            }));
            return steps;
        }
        if (profile != "loader-like")
        {
            return null;
        }
        steps.Add(new Step("file-drop", "write a non-executable payload stand-in to %TEMP%\\workbench-simulator\\stage2.bin", delegate
        {
            Directory.CreateDirectory(work);
            byte[] payload = Encoding.ASCII.GetBytes(Marker + " payload stand-in; not code\r\n");
            File.WriteAllBytes(stage, payload);
        }));
        steps.Add(new Step("registry-config", "write HKCU\\" + ConfigKey + " values", delegate
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(ConfigKey))
            {
                key.SetValue("stage", stage);
                key.SetValue("marker", Marker);
            }
        }));
        steps.Add(new Step("registry-run", "write HKCU Run value " + RunValue + " pointing at the stand-in (removed at exit)", delegate
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RunKey))
            {
                key.SetValue(RunValue, "\"" + stage + "\"");
            }
        }));
        steps.Add(new Step("child-process", "start cmd.exe /c echo (child process)", delegate
        {
            ProcessStartInfo info = new ProcessStartInfo(
                Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                "/c echo workbench-simulator child");
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardOutput = true;
            using (Process child = Process.Start(info))
            {
                child.StandardOutput.ReadToEnd();
                if (!child.WaitForExit(30000))
                {
                    child.Kill();
                }
            }
        }));
        steps.Add(new Step("network-dns", "resolve " + InvalidHost + " (reserved name, never exists)", delegate
        {
            Dns.GetHostEntry(InvalidHost);
        }));
        steps.Add(new Step("network-connect", "TCP connect attempt to " + TestNetAddress + ":443 (TEST-NET-1, never routed), 3 s limit", delegate
        {
            using (TcpClient client = new TcpClient())
            {
                IAsyncResult pending = client.BeginConnect(IPAddress.Parse(TestNetAddress), 443, null, null);
                bool done = pending.AsyncWaitHandle.WaitOne(3000);
                if (!done)
                {
                    throw new TimeoutException();
                }
                client.EndConnect(pending);
            }
        }));
        return steps;
    }

    private static void Cleanup(string work)
    {
        try
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunKey, true))
            {
                if (key != null && key.GetValue(RunValue) != null)
                {
                    key.DeleteValue(RunValue);
                }
            }
        }
        catch (Exception)
        {
        }
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(ConfigKey, false);
        }
        catch (Exception)
        {
        }
        try
        {
            if (Directory.Exists(work))
            {
                Directory.Delete(work, true);
            }
        }
        catch (Exception)
        {
        }
        Console.WriteLine("cleanup done");
    }
}
