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
            logger.Info("Starting string decryption...");
            
            int totalCallsFound = 0;
            int largeValuesFound = 0;

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
                        totalCallsFound++;
                        var encryptedValue = instr[i - 1].GetLdcI4Value();
                        
                        // FOCUS ON LARGE VALUES (likely real strings)
                        if (Math.Abs(encryptedValue) > 1000)
                        {
                            largeValuesFound++;
                            logger.Warning($"LARGE ENCRYPTED: {encryptedValue} (0x{encryptedValue:X8}) in {decMethod.Name}");
                            
                            // Try multiple XOR keys on large values
                            TryDecryptLargeValue(encryptedValue, decMethod, instr, i, logger);
                        }
                        else
                        {
                            // Small values - try simple XOR
                            TryDecryptSmallValue(encryptedValue, instr, i, logger);
                        }
                    }
                }
            }
            
            logger.Info($"=== SUMMARY ===");
            logger.Info($"Total decryption calls found: {totalCallsFound}");
            logger.Info($"Large encrypted values: {largeValuesFound}");
            logger.Info($"Successfully decrypted: {DecryptedStrings}");
        }
        
        private static void TryDecryptSmallValue(int encrypted, Instruction[] instr, int index, Utils.ILogger logger)
        {
            // Try common XOR keys for small values
            int[] keys = { 0x2A, 0x7F, 0xFF, 0x2D, 0x5A, 0xA5 };
            
            foreach (var key in keys)
            {
                int test = encrypted ^ key;
                if (test >= 32 && test <= 126) // Printable ASCII
                {
                    string decrypted = new string((char)test, 1);
                    
                    instr[index - 1].OpCode = OpCodes.Nop;
                    instr[index].OpCode = OpCodes.Ldstr;
                    instr[index].Operand = decrypted;
                    
                    DecryptedStrings++;
                    logger.Success($"Small XOR {key:X}: '{decrypted}' from {encrypted}");
                    return;
                }
            }
        }
        
        private static void TryDecryptLargeValue(int encrypted, IMethod decMethod, Instruction[] instr, int index, Utils.ILogger logger)
        {
            // For large values, we need to analyze the actual decryption method
            var targetMethod = decMethod.ResolveMethodDef();
            if (targetMethod == null || !targetMethod.HasBody)
            {
                logger.Error($"Cannot resolve method: {decMethod.Name}");
                return;
            }
            
            // LOG THE DECRYPTION METHOD IL
            logger.Info($"=== Analyzing {decMethod.Name} ===");
            foreach (var il in targetMethod.Body.Instructions)
            {
                logger.Info($"  {il.OpCode} {il.Operand}");
            }
            
            // Try to decrypt based on IL pattern
            string decrypted = DecryptFromILPattern(encrypted, targetMethod);
            
            if (decrypted != null)
            {
                instr[index - 1].OpCode = OpCodes.Nop;
                instr[index].OpCode = OpCodes.Ldstr;
                instr[index].Operand = decrypted;
                
                DecryptedStrings++;
                logger.Success($"DECRYPTED: '{decrypted}' from {encrypted}");
            }
            else
            {
                // Try brute force XOR with common keys
                for (int key = 0x0000; key <= 0xFFFF; key += 0x0100)
                {
                    int test = encrypted ^ key;
                    byte[] bytes = BitConverter.GetBytes(test);
                    string str = Encoding.ASCII.GetString(bytes).Trim('\0');
                    
                    if (str.Length >= 2 && str.All(c => c >= 32 && c <= 126))
                    {
                        logger.Warning($"Possible XOR {key:X4}: '{str}' from {encrypted}");
                    }
                }
            }
        }
        
        private static string DecryptFromILPattern(int encrypted, MethodDef method)
        {
            var instr = method.Body.Instructions;
            
            // Pattern 1: Simple XOR
            if (instr.Count == 3 && 
                instr[0].OpCode == OpCodes.Ldarg_0 &&
                instr[1].IsLdcI4() &&
                instr[2].OpCode.Code == Code.Xor)
            {
                int key = instr[1].GetLdcI4Value();
                int result = encrypted ^ key;
                return DecodeToString(result);
            }
            
            // Add more patterns as we discover them...
            
            return null;
        }
        
        private static string DecodeToString(int value)
        {
            // Try as 4-byte ASCII string
            byte[] bytes = BitConverter.GetBytes(value);
            Array.Reverse(bytes); // Try both endianness
            
            string ascii = Encoding.ASCII.GetString(bytes).Trim('\0');
            if (ascii.Length > 0 && ascii.All(c => c >= 32 && c <= 126))
                return ascii;
            
            // Try as UTF-16
            string unicode = Encoding.Unicode.GetString(bytes).Trim('\0');
            if (unicode.Length > 0 && unicode.All(c => !char.IsControl(c) || c == '\n' || c == '\r'))
                return unicode;
            
            return null;
        }
    }
}
