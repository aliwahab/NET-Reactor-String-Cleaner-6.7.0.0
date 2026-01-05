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
            logger.Info("=== STRING DECRYPTION ===");
            
            // STEP 1: Find string data
            byte[] stringData = FindStringData(ctx.Module);
            if (stringData == null)
            {
                logger.Error("No string data found!");
                return;
            }
            
            logger.Success($"String data: {stringData.Length} bytes");
            
            // STEP 2: Find decryptor methods
            var decryptors = FindDecryptors(ctx.Module);
            logger.Info($"Found {decryptors.Count} decryptors");
            
            // STEP 3: Process all calls
            int processed = ProcessAllCalls(ctx.Module, decryptors, stringData, logger);
            
            logger.Info($"Processed {processed} calls");
            logger.Success($"Decrypted {DecryptedStrings} strings");
        }
        
        private static byte[] FindStringData(ModuleDefMD module)
        {
            // Check <Module> class
            var moduleType = module.GlobalType;
            if (moduleType != null)
            {
                foreach (var field in moduleType.Fields)
                {
                    if (field.IsStatic && field.InitialValue != null && field.InitialValue.Length > 100)
                    {
                        return field.InitialValue;
                    }
                }
            }
            return null;
        }
        
        private static System.Collections.Generic.List<IMethod> FindDecryptors(ModuleDefMD module)
        {
            var list = new System.Collections.Generic.List<IMethod>();
            
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (method.MethodSig != null &&
                        method.MethodSig.Params.Count == 1 &&
                        method.MethodSig.Params[0].FullName == "System.Int32" &&
                        method.MethodSig.RetType.FullName == "System.String")
                    {
                        list.Add(method);
                    }
                }
            }
            
            return list;
        }
        
        private static int ProcessAllCalls(ModuleDefMD module, System.Collections.Generic.List<IMethod> decryptors, 
                                          byte[] stringData, Utils.ILogger logger)
        {
            int processed = 0;
            
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (method.HasBody)
                    {
                        processed += ProcessMethod(method, decryptors, stringData, logger);
                    }
                }
            }
            
            return processed;
        }
        
        private static int ProcessMethod(MethodDef method, System.Collections.Generic.List<IMethod> decryptors, 
                                        byte[] stringData, Utils.ILogger logger)
        {
            int processed = 0;
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Call && instructions[i].Operand is IMethod calledMethod)
                {
                    if (decryptors.Contains(calledMethod))
                    {
                        int? index = FindIntegerArgument(instructions, i);
                        
                        if (index.HasValue)
                        {
                            string decrypted = DecryptString(index.Value, stringData);
                            
                            if (!string.IsNullOrEmpty(decrypted))
                            {
                                ReplaceWithString(instructions, i, decrypted);
                                DecryptedStrings++;
                                processed++;
                                
                                if (decrypted.Length > 1 && decrypted.Length < 50)
                                {
                                    logger.Success($"[{index.Value}] '{decrypted}'");
                                }
                            }
                        }
                    }
                }
            }
            
            return processed;
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
        
        private static string DecryptString(int index, byte[] data)
        {
            try
            {
                // Try as direct index
                if (index >= 0 && index < data.Length)
                {
                    return ReadString(data, index);
                }
                
                // Try as negative offset
                if (index < 0)
                {
                    int positive = data.Length + index;
                    if (positive >= 0 && positive < data.Length)
                    {
                        return ReadString(data, positive);
                    }
                }
                
                // Try common XOR keys
                int[] keys = { 0x2A, 0x7F, 0xFF, 0x100, 0x55555555 };
                
                foreach (int key in keys)
                {
                    int decoded = index ^ key;
                    
                    if (decoded >= 0 && decoded < data.Length)
                    {
                        string result = ReadString(data, decoded);
                        if (result != null) return result;
                    }
                }
            }
            catch { }
            
            return null;
        }
        
        private static string ReadString(byte[] data, int offset)
        {
            if (offset < 0 || offset >= data.Length) return null;
            
            // Try 4-byte length + UTF8
            if (offset + 4 <= data.Length)
            {
                // FIXED: Use BitConverter to avoid uint/int conversion
                int length = BitConverter.ToInt32(data, offset);
                
                if (length > 0 && length < 1000 && offset + 4 + length <= data.Length)
                {
                    return Encoding.UTF8.GetString(data, offset + 4, length);
                }
            }
            
            // Try null-terminated
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
            
            return null;
        }
        
        private static void ReplaceWithString(System.Collections.Generic.IList<Instruction> instructions, int callIndex, string decrypted)
        {
            instructions[callIndex].OpCode = OpCodes.Ldstr;
            instructions[callIndex].Operand = decrypted;
        }
    }
}
