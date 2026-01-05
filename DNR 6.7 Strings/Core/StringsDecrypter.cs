using System;
using System.Linq;
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
            logger.Info("Starting ConfuserEx 1.6 string decryption...");

            foreach (var typeDef in ctx.Module.GetTypes().Where(x => x.HasMethods))
            foreach (var methodDef in typeDef.Methods.Where(x => x.HasBody)) 
            {
                var instr = methodDef.Body.Instructions;
                
                // Don't simplify/optimize yet - it might break pattern matching
                // methodDef.Body.SimplifyBranches();
                
                for (var i = 0; i < instr.Count; i++)
                {
                    // Pattern: ldc.i4 -> call ???????????????? (string decrypter)
                    if (instr[i].OpCode == OpCodes.Call && 
                        instr[i].Operand is IMethod decMethod &&
                        i > 0 && instr[i - 1].IsLdcI4())
                    {
                        try 
                        {
                            var encryptedValue = instr[i - 1].GetLdcI4Value();
                            
                            // Get method name for logging
                            var methodName = decMethod.Name;
                            if (methodName.Contains("?"))
                                methodName = "ObfuscatedDecryptor";
                            
                            // Try to decrypt based on ConfuserEx 1.6 patterns
                            string decrypted = DecryptConfuserEx16(encryptedValue, decMethod, ctx.Module);
                            
                            if (decrypted != null)
                            {
                                // Replace the call with the decrypted string
                                instr[i - 1].OpCode = OpCodes.Nop;
                                instr[i].OpCode = OpCodes.Ldstr;
                                instr[i].Operand = decrypted;
                                
                                DecryptedStrings++;
                                logger.Success($"Decrypted: '{decrypted}' (from: {encryptedValue})");
                            }
                            else
                            {
                                logger.Warning($"Found encrypted value: {encryptedValue} in {methodName}");
                            }
                        }
                        catch (Exception e) 
                        {
                            logger.Error($"Error: {e.Message}");
                        }
                    }
                }
                
                // Optimize after processing
                // methodDef.Body.OptimizeMacros();
            }
            
            logger.Success($"Decrypted {DecryptedStrings} strings!");
        }
        
        private static string DecryptConfuserEx16(int encrypted, IMethod decMethod, ModuleDefMD module)
        {
            // ConfuserEx 1.6 common patterns:
            
            // 1. Simple XOR pattern: value ^ key
            // 2. Add/Subtract with key
            // 3. Mixed arithmetic
            
            // Try common XOR keys (ConfuserEx often uses 0x2A, 0x7F, etc.)
            int[] commonKeys = { 0x2A, 0x7F, 0xFF, 0x100, 0x2D, 0x5A, 0xA5 };
            
            foreach (var key in commonKeys)
            {
                int result = encrypted ^ key;
                
                // Check if result looks like a string pointer or valid chars
                // Simple heuristic: result in printable ASCII range
                if (result > 0x20 && result < 0x7F)
                {
                    return new string((char)result, 1);
                }
                
                // Try as string (UTF-16 chars)
                byte[] bytes = BitConverter.GetBytes(result);
                string asString = System.Text.Encoding.Unicode.GetString(bytes);
                if (IsPrintable(asString))
                {
                    return asString.Trim('\0');
                }
            }
            
            // If XOR doesn't work, try to analyze the actual decryption method
            var methodDef = decMethod.ResolveMethodDef();
            if (methodDef != null && methodDef.HasBody)
            {
                return AnalyzeDecryptionMethod(encrypted, methodDef);
            }
            
            return null;
        }
        
        private static string AnalyzeDecryptionMethod(int encrypted, MethodDef methodDef)
        {
            // Analyze the IL of the decryption method
            // ConfuserEx patterns often look like:
            // ldc.i4 X
            // ldc.i4 KEY
            // xor (or add/sub/...)
            // ret
            
            var instr = methodDef.Body.Instructions;
            int? key = null;
            OpCode? operation = null;
            
            for (int i = 0; i < instr.Count; i++)
            {
                if (instr[i].IsLdcI4())
                {
                    int value = instr[i].GetLdcI4Value();
                    
                    // Skip the encrypted value parameter
                    if (i == 0 && value == encrypted) continue;
                    
                    key = value;
                }
                else if (instr[i].OpCode == OpCodes.Xor)
                {
                    operation = OpCodes.Xor;
                }
                else if (instr[i].OpCode == OpCodes.Add)
                {
                    operation = OpCodes.Add;
                }
                else if (instr[i].OpCode == OpCodes.Sub)
                {
                    operation = OpCodes.Sub;
                }
            }
            
            if (key.HasValue && operation.HasValue)
            {
                int result = operation.Value == OpCodes.Xor ? encrypted ^ key.Value :
                            operation.Value == OpCodes.Add ? encrypted + key.Value :
                            encrypted - key.Value;
                
                // Convert to string
                try
                {
                    byte[] bytes = BitConverter.GetBytes(result);
                    string str = System.Text.Encoding.Unicode.GetString(bytes).Trim('\0');
                    if (IsPrintable(str)) return str;
                }
                catch { }
            }
            
            return null;
        }
        
        private static bool IsPrintable(string str)
        {
            if (string.IsNullOrEmpty(str)) return false;
            
            foreach (char c in str)
            {
                if (c == '\0') continue;
                if (char.IsControl(c) && c != '\n' && c != '\r' && c != '\t')
                    return false;
            }
            return true;
        }
    }
}
