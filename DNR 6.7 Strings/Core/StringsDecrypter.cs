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
            logger.Info("=== CONFUSEREX STRING DECRYPTOR ===");
            
            // STEP 1: Find and analyze string decryption calls
            int callsFound = FindAndLogStringCalls(ctx.Module, logger);
            
            logger.Info($"Total string calls found: {callsFound}");
            
            // STEP 2: Try to decrypt using common patterns
            if (callsFound > 0)
            {
                TryDecryptStrings(ctx.Module, logger);
            }
            
            logger.Success($"Decrypted {DecryptedStrings} strings!");
        }
        
        private static int FindAndLogStringCalls(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("=== SEARCHING FOR STRING CALLS ===");
            int totalCalls = 0;
            
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    
                    totalCalls += LogMethodStringCalls(type, method, logger);
                }
            }
            
            return totalCalls;
        }
        
        private static int LogMethodStringCalls(TypeDef type, MethodDef method, Utils.ILogger logger)
        {
            int callsInMethod = 0;
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                // Look for: ldc.i4 -> call
                if (instructions[i].OpCode == OpCodes.Call && i > 0 && instructions[i - 1].IsLdcI4())
                {
                    int index = instructions[i - 1].GetLdcI4Value();
                    var calledMethod = instructions[i].Operand as IMethod;
                    
                    // Large values are likely string indices
                    if (Math.Abs(index) > 1000 && calledMethod != null)
                    {
                        callsInMethod++;
                        
                        logger.Info($"");
                        logger.Info($"Call #{callsInMethod} in {type.Name}.{method.Name}:");
                        logger.Info($"  Index: {index} (0x{index:X8})");
                        logger.Info($"  Calls: {calledMethod.FullName}");
                        
                        // If it's in <Module> class, it's definitely string decryption
                        if (calledMethod.DeclaringType.FullName == "<Module>")
                        {
                            logger.Warning($"  CONFIRMED: <Module> string decryptor!");
                            
                            // Try to analyze this specific method
                            AnalyzeDecryptorMethod(calledMethod, logger);
                        }
                    }
                }
            }
            
            return callsInMethod;
        }
        
        private static void AnalyzeDecryptorMethod(IMethod method, Utils.ILogger logger)
        {
            try
            {
                var methodDef = method.ResolveMethodDef();
                if (methodDef != null && methodDef.HasBody)
                {
                    logger.Info($"  Method IL analysis:");
                    
                    int instructionCount = 0;
                    foreach (var instr in methodDef.Body.Instructions)
                    {
                        instructionCount++;
                        string operand = instr.Operand?.ToString() ?? "";
                        
                        // Shorten long strings
                        if (operand.Length > 50)
                            operand = operand.Substring(0, 47) + "...";
                        
                        logger.Info($"    {instr.OpCode} {operand}");
                        
                        // Just show first 20 instructions
                        if (instructionCount >= 20)
                        {
                            logger.Info($"    ... and {methodDef.Body.Instructions.Count - 20} more");
                            break;
                        }
                    }
                }
                else
                {
                    logger.Info($"  Could not resolve method body");
                }
            }
            catch (Exception ex)
            {
                logger.Error($"  Error analyzing: {ex.Message}");
            }
        }
        
        private static void TryDecryptStrings(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("");
            logger.Info("=== ATTEMPTING DECRYPTION ===");
            
            // Get string data from <Module>
            byte[] stringData = GetModuleStringData(module, logger);
            if (stringData == null)
            {
                logger.Error("No string data found in <Module>");
                return;
            }
            
            logger.Info($"String data size: {stringData.Length} bytes");
            
            // Process all methods again, this time trying to decrypt
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (method.HasBody)
                    {
                        ProcessMethodForDecryption(method, stringData, logger);
                    }
                }
            }
        }
        
        private static byte[] GetModuleStringData(ModuleDefMD module, Utils.ILogger logger)
        {
            var moduleType = module.GlobalType;
            if (moduleType == null) return null;
            
            foreach (var field in moduleType.Fields)
            {
                // Check if it's a static field with initial value
                if (field.IsStatic && field.InitialValue != null)
                {
                    // Log all static fields for debugging
                    logger.Info($"Found static field: {field.Name} - {field.InitialValue.Length} bytes");
                    
                    // Return the first non-empty array
                    if (field.InitialValue.Length > 0)
                    {
                        return field.InitialValue;
                    }
                }
            }
            
            return null;
        }
        
        private static void ProcessMethodForDecryption(MethodDef method, byte[] stringData, Utils.ILogger logger)
        {
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Call && i > 0 && instructions[i - 1].IsLdcI4())
                {
                    int index = instructions[i - 1].GetLdcI4Value();
                    var calledMethod = instructions[i].Operand as IMethod;
                    
                    if (Math.Abs(index) > 1000 && calledMethod != null && 
                        calledMethod.DeclaringType.FullName == "<Module>")
                    {
                        // Try to decrypt
                        string decrypted = DecryptStringIndex(index, stringData);
                        
                        if (!string.IsNullOrEmpty(decrypted) && decrypted.Length > 0)
                        {
                            // Replace the call with the string
                            instructions[i - 1].OpCode = OpCodes.Nop;
                            instructions[i].OpCode = OpCodes.Ldstr;
                            instructions[i].Operand = decrypted;
                            
                            DecryptedStrings++;
                            
                            // Log success
                            string preview = decrypted.Length > 30 ? 
                                decrypted.Substring(0, 27) + "..." : decrypted;
                            logger.Success($"Decrypted: '{preview}'");
                        }
                    }
                }
            }
        }
        
        private static string DecryptStringIndex(int index, byte[] data)
        {
            try
            {
                // COMMON CONFUSEREX PATTERNS:
                
                // Pattern 1: Index is byte offset (for small values)
                if (index >= 0 && index < data.Length)
                {
                    return TryReadStringAtOffset(data, index);
                }
                
                // Pattern 2: Negative index = offset from end
                if (index < 0)
                {
                    int positiveIndex = data.Length + index;
                    if (positiveIndex >= 0 && positiveIndex < data.Length)
                    {
                        return TryReadStringAtOffset(data, positiveIndex);
                    }
                }
                
                // Pattern 3: Index * 4 = byte offset (common in ConfuserEx)
                int byteOffset = index * 4;
                
                // Handle overflow/negative
                if (byteOffset < 0)
                {
                    byteOffset = data.Length + byteOffset;
                }
                
                if (byteOffset >= 0 && byteOffset < data.Length)
                {
                    return TryReadStringAtOffset(data, byteOffset);
                }
                
                // Pattern 4: Try XOR with common keys
                int[] xorKeys = { 0x2A, 0x7F, 0xFF, 0x100, 0x55555555, 0xAAAAAAAA };
                
                foreach (int key in xorKeys)
                {
                    int decoded = index ^ key;
                    
                    // Try as direct offset
                    if (decoded >= 0 && decoded < data.Length)
                    {
                        string result = TryReadStringAtOffset(data, decoded);
                        if (result != null) return result;
                    }
                    
                    // Try as negative offset
                    if (decoded < 0)
                    {
                        int positive = data.Length + decoded;
                        if (positive >= 0 && positive < data.Length)
                        {
                            string result = TryReadStringAtOffset(data, positive);
                            if (result != null) return result;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return null;
            }
            
            return null;
        }
        
        private static string TryReadStringAtOffset(byte[] data, int offset)
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
                        string result = Encoding.UTF8.GetString(data, offset + 4, length);
                        return CleanString(result);
                    }
                }
                
                // Try null-terminated string
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
                
                // Try as raw ASCII
                int maxLength = Math.Min(100, data.Length - offset);
                string ascii = Encoding.ASCII.GetString(data, offset, maxLength);
                ascii = ascii.Split('\0')[0]; // Take until first null
                
                if (ascii.Length > 0 && IsReadableAscii(ascii))
                {
                    return ascii;
                }
            }
            catch { }
            
            return null;
        }
        
        private static string CleanString(string str)
        {
            if (string.IsNullOrEmpty(str)) return str;
            
            // Remove control characters
            var result = new StringBuilder();
            foreach (char c in str)
            {
                if (c == '\0') continue;
                if (char.IsControl(c) && c != '\n' && c != '\r' && c != '\t')
                    continue;
                result.Append(c);
            }
            
            return result.ToString().Trim();
        }
        
        private static bool IsReadableAscii(string str)
        {
            foreach (char c in str)
            {
                if (c < 32 || c > 126) return false;
            }
            return true;
        }
    }
}
