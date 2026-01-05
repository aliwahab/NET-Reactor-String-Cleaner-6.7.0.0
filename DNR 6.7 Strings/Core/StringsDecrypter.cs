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
            logger.Info("=== STRING DECRYPTION START ===");
            
            // STEP 1: Find the string data (array of bytes in <Module> class)
            byte[] stringData = FindStringData(ctx.Module, logger);
            if (stringData == null)
            {
                logger.Error("ERROR: Could not find string data array!");
                return;
            }
            
            logger.Success($"Found string data: {stringData.Length} bytes");
            
            // STEP 2: Find ALL string decryption methods
            var decryptors = FindAllDecryptors(ctx.Module, logger);
            logger.Info($"Found {decryptors.Count} string decryptor methods");
            
            // STEP 3: Process ALL calls to these decryptors
            ProcessDecryptorCalls(ctx.Module, decryptors, stringData, logger);
            
            logger.Success($"=== COMPLETE: Decrypted {DecryptedStrings} strings ===");
        }
        
        // ==================== STEP 1: FIND STRING DATA ====================
        private static byte[] FindStringData(ModuleDefMD module, Utils.ILogger logger)
        {
            // Look in <Module> class first (most common)
            var moduleType = module.GlobalType;
            if (moduleType != null)
            {
                foreach (var field in moduleType.Fields)
                {
                    if (field.IsStatic && 
                        field.InitialValue != null && 
                        field.InitialValue.Length > 100)
                    {
                        logger.Info($"Found static array in <Module>: {field.InitialValue.Length} bytes");
                        return field.InitialValue;
                    }
                }
            }
            
            return null;
        }
        
        // ==================== STEP 2: FIND DECRYPTOR METHODS ====================
        private static System.Collections.Generic.List<IMethod> FindAllDecryptors(ModuleDefMD module, Utils.ILogger logger)
        {
            var methods = new System.Collections.Generic.List<IMethod>();
            
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    // Method signature: string Method(int)
                    if (method.MethodSig != null &&
                        method.MethodSig.Params.Count == 1 &&
                        method.MethodSig.Params[0].FullName == "System.Int32" &&
                        method.MethodSig.RetType.FullName == "System.String")
                    {
                        methods.Add(method);
                    }
                }
            }
            
            return methods;
        }
        
        // ==================== STEP 3: PROCESS ALL CALLS ====================
        private static void ProcessDecryptorCalls(ModuleDefMD module, System.Collections.Generic.List<IMethod> decryptors, 
                                                 byte[] stringData, Utils.ILogger logger)
        {
            int totalCalls = 0;
            
            foreach (var type in module.GetTypes().Where(t => t.HasMethods))
            {
                foreach (var method in type.Methods.Where(m => m.HasBody))
                {
                    totalCalls += ProcessMethod(method, decryptors, stringData, logger);
                }
            }
            
            logger.Info($"Processed {totalCalls} method calls");
        }
        
        private static int ProcessMethod(MethodDef method, System.Collections.Generic.List<IMethod> decryptors, 
                                        byte[] stringData, Utils.ILogger logger)
        {
            int callsProcessed = 0;
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                // Look for: call string Decryptor(int)
                if (instructions[i].OpCode == OpCodes.Call && 
                    instructions[i].Operand is IMethod calledMethod &&
                    decryptors.Contains(calledMethod))
                {
                    // Find the integer argument (ldc.i4 before the call)
                    int? stringIndex = FindIntegerArgument(instructions, i);
                    
                    if (stringIndex.HasValue)
                    {
                        // Try to decrypt the string
                        string decrypted = TryDecryptString(stringIndex.Value, stringData);
                        
                        if (!string.IsNullOrEmpty(decrypted))
                        {
                            // Replace: ldc.i4 VALUE -> call Decryptor
                            // With:    nop         -> ldstr "DECRYPTED"
                            ReplaceCallWithString(instructions, i, stringIndex.Value, decrypted);
                            
                            DecryptedStrings++;
                            callsProcessed++;
                            
                            // Log interesting strings
                            if (decrypted.Length > 1 && decrypted.Length < 100)
                            {
                                logger.Success($"'{decrypted}'");
                            }
                        }
                    }
                }
            }
            
            return callsProcessed;
        }
        
        // ==================== STRING DECRYPTION LOGIC ====================
        private static string TryDecryptString(int index, byte[] data)
        {
            try
            {
                // METHOD A: If index is small, use as direct offset
                if (index >= 0 && index < data.Length)
                {
                    return DecodeStringAtOffset(data, index);
                }
                
                // METHOD B: If index is negative, convert to positive offset from end
                if (index < 0)
                {
                    int positiveIndex = data.Length + index;
                    if (positiveIndex >= 0 && positiveIndex < data.Length)
                    {
                        return DecodeStringAtOffset(data, positiveIndex);
                    }
                }
                
                // METHOD C: Try XOR with common keys (ConfuserEx sometimes encodes indices)
                int[] commonKeys = { 0x2A, 0x7F, 0xFF, 0x100, 0x55555555, 0xAAAAAAAA };
                
                foreach (int key in commonKeys)
                {
                    int decoded = index ^ key;
                    
                    // Try as direct index
                    if (decoded >= 0 && decoded < data.Length)
                    {
                        string result = DecodeStringAtOffset(data, decoded);
                        if (result != null) return result;
                    }
                    
                    // Try as negative index
                    if (decoded < 0)
                    {
                        int positive = data.Length + decoded;
                        if (positive >= 0 && positive < data.Length)
                        {
                            string result = DecodeStringAtOffset(data, positive);
                            if (result != null) return result;
                        }
                    }
                }
            }
            catch { }
            
            return null;
        }
        
        private static string DecodeStringAtOffset(byte[] data, int offset)
        {
            if (offset < 0 || offset >= data.Length) return null;
            
            // PATTERN 1: 4-byte length + UTF8 string
            if (offset + 4 <= data.Length)
            {
                int length = BitConverter.ToInt32(data, offset);
                if (length > 0 && length <= 1000 && offset + 4 + length <= data.Length)
                {
                    return Encoding.UTF8.GetString(data, offset + 4, length).Replace("\0", "");
                }
            }
            
            // PATTERN 2: Null-terminated string
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
        
        // ==================== HELPER METHODS ====================
        private static int? FindIntegerArgument(System.Collections.Generic.IList<Instruction> instructions, int callIndex)
        {
            // Look backwards for ldc.i4 (up to 5 instructions)
            for (int i = callIndex - 1; i >= 0 && i >= callIndex - 5; i--)
            {
                if (instructions[i].IsLdcI4())
                {
                    return instructions[i].GetLdcI4Value();
                }
            }
            return null;
        }
        
        private static void ReplaceCallWithString(System.Collections.Generic.IList<Instruction> instructions, 
                                                 int callIndex, int originalIndex, string decrypted)
        {
            // Find and remove the ldc.i4 instruction
            for (int i = callIndex - 1; i >= 0 && i >= callIndex - 5; i--)
            {
                if (instructions[i].IsLdcI4() && instructions[i].GetLdcI4Value() == originalIndex)
                {
                    instructions[i].OpCode = OpCodes.Nop;
                    instructions[i].Operand = null;
                    break;
                }
            }
            
            // Replace call with the string
            instructions[callIndex].OpCode = OpCodes.Ldstr;
            instructions[callIndex].Operand = decrypted;
        }
    }
}
