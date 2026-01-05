using System;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNR.Core
{
    public static class StringsDecrypter
    {
        public static int DecryptedStrings { get; private set; }

        public static void Execute(Context ctx)
        {
            var logger = ctx.Options.Logger;
            logger.Info("=== STRING DECRYPTION v2 ===");
            
            // STEP 1: Find ALL possible decryptors
            var decryptors = FindAllPossibleDecryptors(ctx.Module, logger);
            logger.Info($"Found {decryptors.Count} potential decryptors");
            
            if (decryptors.Count == 0)
            {
                logger.Error("No decryptors found! Searching manually...");
                SearchManually(ctx.Module, logger);
                return;
            }
            
            // STEP 2: Find string data
            byte[] stringData = FindStringData(ctx.Module);
            if (stringData == null)
            {
                logger.Error("No string data!");
                return;
            }
            
            logger.Success($"String data: {stringData.Length} bytes");
            
            // DEBUG: Show first bytes
            logger.Info($"First 32 bytes: {BitConverter.ToString(stringData, 0, Math.Min(32, stringData.Length))}");
            
            // STEP 3: Process ALL calls in module
            ProcessModule(ctx.Module, stringData, decryptors, logger);
            
            logger.Success($"Decrypted {DecryptedStrings} strings!");
        }
        
        private static System.Collections.Generic.List<object> FindAllPossibleDecryptors(ModuleDefMD module, Utils.ILogger logger)
        {
            var list = new System.Collections.Generic.List<object>();
            
            // Look in EVERY type
            foreach (var type in module.GetTypes())
            {
                // 1. Methods that might decrypt strings
                foreach (var method in type.Methods)
                {
                    if (method.MethodSig == null) continue;
                    
                    // Any method taking int could be string decryptor
                    if (method.MethodSig.Params.Count == 1)
                    {
                        var paramType = method.MethodSig.Params[0];
                        if (paramType != null && paramType.FullName == "System.Int32")
                        {
                            list.Add(method);
                        }
                    }
                }
                
                // 2. Static fields in <Module> class (often hold delegates)
                if (type.FullName == "<Module>")
                {
                    foreach (var field in type.Fields)
                    {
                        if (field.IsStatic)
                        {
                            list.Add(field);
                        }
                    }
                }
            }
            
            return list;
        }
        
        private static void SearchManually(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("=== MANUAL SEARCH ===");
            
            // Look for calls with ldc.i4 before them
            int callCount = 0;
            
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    
                    var instructions = method.Body.Instructions;
                    for (int i = 0; i < instructions.Count; i++)
                    {
                        // Look for: ldc.i4 SOME_LARGE_NUMBER -> call SOME_METHOD
                        if (instructions[i].OpCode == OpCodes.Call && i > 0 && instructions[i - 1].IsLdcI4())
                        {
                            int value = instructions[i - 1].GetLdcI4Value();
                            
                            // Large values are likely string indices
                            if (Math.Abs(value) > 1000)
                            {
                                callCount++;
                                logger.Warning($"Found at {type.Name}.{method.Name}:");
                                logger.Warning($"  ldc.i4 {value}");
                                logger.Warning($"  call {instructions[i].Operand}");
                            }
                        }
                    }
                }
            }
            
            logger.Info($"Total string-like calls found: {callCount}");
        }
        
        private static byte[] FindStringData(ModuleDefMD module)
        {
            var moduleType = module.GlobalType;
            if (moduleType != null)
            {
                foreach (var field in moduleType.Fields)
                {
                    if (field.IsStatic && field.InitialValue != null)
                    {
                        return field.InitialValue;
                    }
                }
            }
            return null;
        }
        
        private static void ProcessModule(ModuleDefMD module, byte[] stringData, 
                                         System.Collections.Generic.List<object> decryptors, Utils.ILogger logger)
        {
            int processed = 0;
            
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (method.HasBody)
                    {
                        processed += ProcessMethod(method, stringData, decryptors, logger);
                    }
                }
            }
            
            logger.Info($"Processed {processed} method calls");
        }
        
        private static int ProcessMethod(MethodDef method, byte[] stringData, 
                                        System.Collections.Generic.List<object> decryptors, Utils.ILogger logger)
        {
            int processed = 0;
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Call)
                {
                    // Get the called method/field
                    object target = GetCallTarget(instructions[i]);
                    
                    if (target != null && decryptors.Contains(target))
                    {
                        // Find the integer argument
                        int? index = FindIntegerArgument(instructions, i);
                        
                        if (index.HasValue)
                        {
                            // Try to decrypt
                            string decrypted = TryAllDecryptionMethods(index.Value, stringData);
                            
                            if (!string.IsNullOrEmpty(decrypted))
                            {
                                // Replace the call
                                ReplaceCall(instructions, i, decrypted);
                                DecryptedStrings++;
                                processed++;
                                
                                logger.Success($"[{index.Value}] '{decrypted}'");
                            }
                        }
                    }
                }
            }
            
            return processed;
        }
        
        private static object GetCallTarget(Instruction instruction)
        {
            if (instruction.Operand is IMethod method) return method;
            if (instruction.Operand is IField field) return field;
            return null;
        }
        
        private static int? FindIntegerArgument(System.Collections.Generic.IList<Instruction> instructions, int callIndex)
        {
            for (int i = callIndex - 1; i >= 0 && i >= callIndex - 5; i--)
            {
                if (instructions[i].IsLdcI4())
                {
                    return instructions[i].GetLdcI4Value();
                }
            }
            return null;
        }
        
        private static string TryAllDecryptionMethods(int index, byte[] data)
        {
            // Try multiple approaches
            
            // 1. Direct index
            if (index >= 0 && index < data.Length)
            {
                string result = ReadString(data, index);
                if (result != null) return result;
            }
            
            // 2. Negative index (offset from end)
            if (index < 0)
            {
                int positive = data.Length + index;
                if (positive >= 0 && positive < data.Length)
                {
                    string result = ReadString(data, positive);
                    if (result != null) return result;
                }
            }
            
            // 3. Try XOR with common keys
            int[] keys = { 0x2A, 0x7F, 0xFF, 0x100, 0x55555555, 0x2D, 0x5A, 0xA5 };
            
            foreach (int key in keys)
            {
                int decoded = index ^ key;
                
                if (decoded >= 0 && decoded < data.Length)
                {
                    string result = ReadString(data, decoded);
                    if (result != null) return result;
                }
                
                if (decoded < 0)
                {
                    int positive = data.Length + decoded;
                    if (positive >= 0 && positive < data.Length)
                    {
                        string result = ReadString(data, positive);
                        if (result != null) return result;
                    }
                }
            }
            
            return null;
        }
        
        private static string ReadString(byte[] data, int offset)
        {
            if (offset < 0 || offset >= data.Length) return null;
            
            try
            {
                // Try 4-byte length + UTF8
                if (offset + 4 <= data.Length)
                {
                    int length = BitConverter.ToInt32(data, offset);
                    
                    if (length > 0 && length < 1000 && offset + 4 + length <= data.Length)
                    {
                        return Encoding.UTF8.GetString(data, offset + 4, length);
                    }
                }
                
                // Try null-terminated UTF8
                for (int i = offset; i < data.Length; i++)
                {
                    if (data[i] == 0)
                    {
                        int length = i - offset;
                        if (length > 0)
                        {
                            return Encoding.UTF8.GetString(data, offset, length);
                        }
                        break;
                    }
                }
            }
            catch { }
            
            return null;
        }
        
        private static void ReplaceCall(System.Collections.Generic.IList<Instruction> instructions, int callIndex, string decrypted)
        {
            instructions[callIndex].OpCode = OpCodes.Ldstr;
            instructions[callIndex].Operand = decrypted;
        }
    }
}
