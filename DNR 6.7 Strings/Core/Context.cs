using System;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

namespace DNR.Core
{
    public class Context
    {
        public Context(CtxOptions ctxOptions)
        {
            Options = ctxOptions;
            Module = ModuleDefMD.Load(Options.FilePath);
            
            // REMOVE THIS LINE - causes BadImageFormatException
            // Asm = Assembly.UnsafeLoadFrom(Options.FilePath);
            
            Console.WriteLine($"[INFO] Loaded: {Module.Name}");
        }

        public CtxOptions Options { get; }
        public ModuleDefMD Module { get; }

        public void Save()
        {
            var writerOptions = new ModuleWriterOptions(Module)
            {
                Logger = DummyLogger.NoThrowInstance,
                MetadataOptions = { Flags = MetadataFlags.PreserveAll & MetadataFlags.KeepOldMaxStack }
            };

            Module.Write(Options.OutputPath, writerOptions);
            Console.WriteLine($"[INFO] Saved to: {Options.OutputPath}");
        }
    }
}
