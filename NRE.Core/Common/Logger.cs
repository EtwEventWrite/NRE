using System;

namespace NRE.Core.Common
{
/// <summary>
/// Simple logger for builder; stub typically does not log.
/// </summary>
public static class Logger
{
    public static void Info(string message) => Console.WriteLine("[*] " + message);
    public static void Success(string message) => Console.WriteLine("[+] " + message);
    public static void Error(string message) => Console.Error.WriteLine("[-] " + message);
    public static void Warn(string message) => Console.WriteLine("[!] " + message);
    public static void Debug(string message) => Console.WriteLine("[.] " + message);
}
}
