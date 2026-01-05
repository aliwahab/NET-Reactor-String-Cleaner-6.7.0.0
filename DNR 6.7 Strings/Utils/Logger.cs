using System;

namespace DNR.Utils
{
    internal class Logger : ILogger
    {
        public void Debug(string message)
        {
            WriteWithColor($"[-] {message}", ConsoleColor.DarkGray);
        }

        public void Info(string message)
        {
            WriteWithColor($"[*] {message}", ConsoleColor.Cyan);
        }

        public void Warning(string message)
        {
            WriteWithColor($"[!] {message}", ConsoleColor.Yellow);
        }

        public void Error(string message)
        {
            WriteWithColor($"[#] {message}", ConsoleColor.Red);
        }

        public void Success(string message)
        {
            WriteWithColor($"[+] {message}", ConsoleColor.Green);
        }

        private void WriteWithColor(string message, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ResetColor();
        }
    }
}
