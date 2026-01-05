using System;
using System.Diagnostics;
using DNR.Utils;
using DNR.Core;  // ADD THIS LINE - fixes missing classes

namespace DNR
{
    public static class Program
    {
        private static readonly string asciiArt = @"
        _________                __                 
        \_   ___ \  ____________/  |_  ____ ___  ___
        /    \  \/ /  _ \_  __ \   __\/ __ \\  \/  /
        \     \___(  <_> )  | \/|  | \  ___/ >    < 
         \______  /\____/|__|   |__|  \___  >__/\_ \
                \/                        \/      \/
                  .NET Reactor 6.7.0.0 Strings
                 By https://github.com/Hussaryn
                      Credits HoLLy-HaCKeR
         
        ";

        public static void Main(string[] args)
        {
            Console.Title = "DNR 6.7.0.0 Strings decrypter";
            
            // FIXED: Remove Spectre.Console color, use simple Console
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine(asciiArt);
            Console.ResetColor();

            var logger = new Logger();
            var stopwatch = Stopwatch.StartNew();

            if (args.Length < 1) {
                logger.Warning("Usage: DNR 6.7 Strings.exe <path>");
                Console.ReadLine();
                return;
            }

            // FIXED: These classes now available via "using DNR.Core;"
            StacktracePatcher.Patch();

            var options = new CtxOptions(args[0], logger);
            var ctx = new Context(options);
            
            logger.Warning("Use control flow remover first!");
            logger.Info("Executing memory patches...");
            StacktracePatcher.Patch();

            StringsDecrypter.Execute(ctx);
            ctx.Save();

            Console.WriteLine(string.Empty);

            logger.Success($"Decrypted {StringsDecrypter.DecryptedStrings} Strings!");
            logger.Success($"Saved in {ctx.Options.OutputPath}!");

            stopwatch.Stop();
            logger.Success($"Finished all tasks in {stopwatch.Elapsed}");
            Console.ReadKey();
        }
    }
}
