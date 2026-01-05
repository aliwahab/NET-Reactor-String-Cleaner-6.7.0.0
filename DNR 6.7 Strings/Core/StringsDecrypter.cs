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
            logger.Info("DEBUG MODE: Analyzing string encryption...");

            foreach (var typeDef in ctx.Module.GetTypes().Where(x => x.HasMethods))
            foreach (var methodDef in typeDef.Methods.Where(x => x.HasBody)) 
            {
                var instr = methodDef.Body.Instructions;
                
                for (var i = 0; i < instr.Count; i++)
                {
                    if (instr[i].OpCode == OpCodes.Call && 
                        instr[i].Operand is IMethod decMethod &&
                        i > 0 && instr[i - 1].IsLdcI4())
                    {
                        try 
                        {
                            var encryptedValue = instr[i - 1].GetLdcI4Value();
                            
                            logger.Info($"=== ENCRYPTED VALUE: {encryptedValue} (0x{encryptedValue:X8}) ===");
                            logger.Info($"Calling method: {decMethod.FullName}");
                            
                            // RESOLVE AND DUMP THE DECRYPTION METHOD
                            var targetMethod = decMethod.ResolveMethodDef();
                            if (targetMethod != null && targetMethod.HasBody)
                            {
                                logger.Info("Decryption method IL:");
                                foreach (var il in targetMethod.Body.Instructions)
                                {
                                    logger.Info($"  {il.OpCode} {il.Operand}");
                                }
                                
                                // Try to analyze and decrypt
                                string decrypted = TryDecryptFromIL(encryptedValue, targetMethod);
                                if (decrypted != null)
                                {
                                    instr[i - 1].OpCode = OpCodes.Nop;
                                    instr[i].OpCode = OpCodes.Ldstr;
                                    instr[i].Operand = decrypted;
                                    
                                    DecryptedStrings++;
                                    logger.Success($"DECRYPTED: '{decrypted}'");
                                }
                            }
                            else
                            {
                                logger.Warning("Could not resolve decryption method");
                            }
                            
                            logger.Info(""); // Empty line for readability
                        }
                        catch (Exception e) 
                        {
                            logger.Error($"Exception: {e.Message}");
                        }
                    }
                }
            }
            
            logger.Info($"=== ANALYSIS COMPLETE ===");
            logger.Info($"Found {DecryptedStrings} decryptable strings");
        }
        
        private static string TryDecryptFromIL(int encrypted, MethodDef method)
        {
            // Analyze the method body for common patterns
            var instr = method.Body.Instructions;
            var logger = new Logger(); // You'll need to pass logger somehow
            
            // Pattern 1: Simple XOR
            if (instr.Count == 3 && 
                instr[0].OpCode == OpCodes.Ldarg_0 &&
                instr[1].IsLdcI4() &&
                instr[2].OpCode.Code == Code.Xor)
            {
                int key = instr[1].GetLdcI4Value();
                int result = encrypted ^ key;
                return DecodeIntegerToString(result);
            }
            
            // Pattern 2: Simple ADD
            if (instr.Count == 3 && 
                instr[0].OpCode == OpCodes.Ldarg_0 &&
                instr[1].IsLdcI4() &&
                instr[2].OpCode.Code == Code.Add)
            {
                int key = instr[1].GetLdcI4Value();
                int result = encrypted + key;
                return DecodeIntegerToString(result);
            }
            
            // Pattern 3: Simple SUB
            if (instr.Count == 3 && 
                instr[0].OpCode == OpCodes.Ldarg_0 &&
                instr[1].IsLdcI4() &&
                instr[2].OpCode.Code == Code.Sub)
            {
                int key = instr[1].GetLdcI4Value();
                int result = encrypted - key;
                return DecodeIntegerToString(result);
            }
            
            logger.Warning($"Unknown pattern with {instr.Count} instructions");
            return null;
        }
        
        private static string DecodeIntegerToString(int value)
        {
            try
            {
                // Try as UTF-16 string
                byte[] bytes = BitConverter.GetBytes(value);
                string str = Encoding.Unicode.GetString(bytes).Trim('\0');
                
                // Check if it's printable
                if (!string.IsNullOrEmpty(str) && str.All(c => char.IsLetterOrDigit(c) || char.IsPunctuation(c) || c == ' '))
                    return str;
                    
                // Try as ASCII
                str = Encoding.ASCII.GetString(bytes).Trim('\0');
                if (!string.IsNullOrEmpty(str) && str.All(c => c >= 32 && c <= 126))
                    return str;
                    
                // Return as hex for debugging
                return $"[0x{value:X8}]";
            }
            catch
            {
                return $"[{value}]";
            }
        }
    }
}
