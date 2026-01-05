using System;

namespace DNR.Utils
{
    public interface ILogger
    {
        void Debug(string message);
        void Info(string message);
        void Warning(string message);
        void Error(string message);
        void Success(string message);
    }

    internal class Logger : ILogger
    {
        public void Debug(string message)
        {
            WriteColored($"[-] {message}", ConsoleColor.DarkGray);
        }

        public void Info(string message)
        {
            WriteColored($"[*] {message}", ConsoleColor.Cyan);
        }

        public void Warning(string message)
        {
            WriteColored($"[!] {message}", ConsoleColor.Yellow);
        }

        public void Error(string message)
        {
            WriteColored($"[#] {message}", ConsoleColor.Red);
        }

        public void Success(string message)
        {
            WriteColored($"[+] {message}", ConsoleColor.Green);
        }

        private void WriteColored(string message, ConsoleColor color)
        {
            // Save original color
            var originalColor = Console.ForegroundColor;
            
            // Parse and apply colors based on markers
            if (message.Contains("[-]"))
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
            }
            else if (message.Contains("[*]"))
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
            }
            else if (message.Contains("[!]"))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
            }
            else if (message.Contains("[#]"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }
            else if (message.Contains("[+]"))
            {
                Console.ForegroundColor = ConsoleColor.Green;
            }
            else
            {
                Console.ForegroundColor = color;
            }
            
            Console.WriteLine(message);
            Console.ForegroundColor = originalColor;
        }
    }
}
