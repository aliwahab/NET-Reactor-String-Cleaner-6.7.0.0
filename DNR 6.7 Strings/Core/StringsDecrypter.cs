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
            logger.Info("=== STRING DECRYPTION DEBUG MODE ===");
            
            int totalCalls = 0;
            int largeValues = 0;

            foreach (var typeDef in ctx.Module.GetTypes().Where(x => x.HasMethods))
            foreach (var methodDef in typeDef.Methods.Where(x => x.HasBody)) 
            {
                var instructions = methodDef.Body.Instructions;
                
                for (var i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i].OpCode == OpCodes.Call && 
                        instructions[i].Operand is IMethod decMethod &&
                        i > 0 && instructions[i - 1].IsLdcI4())
                    {
                        totalCalls++;
                        var encryptedValue = instructions[i - 1].GetLdcI4Value();
                        
                        // LOG EVERYTHING FOR DEBUGGING
                        logger.Info($"");
                        logger.Info($"=== CALL #{totalCalls} ===");
                        logger.Info($"Location: {typeDef.Name}.{methodDef.Name}");
                        logger.Info($"Encrypted value: {encryptedValue} (0x{encryptedValue:X8})");
                        logger.Info($"Target method: {decMethod.FullName}");
                        
                        // Check if it's a large value (likely real string)
                        if (Math.Abs(encryptedValue) > 1000)
                        {
                            largeValues++;
                            logger.Warning($"LIKELY REAL STRING (value > 1000)");
                            
                            // DUMP THE DECRYPTION METHOD IL
                            var targetMethod = decMethod.ResolveMethodDef();
                            if (targetMethod != null && targetMethod.HasBody)
                            {
                                logger.Info("=== DECRYPTION METHOD IL ===");
                                foreach (var il in targetMethod.Body.Instructions)
                                {
                                    logger.Info($"  {il.OpCode} {il.Operand}");
                                }
                                
                                // Try to understand the algorithm
                                AnalyzeDecryptionMethod(encryptedValue, targetMethod, logger);
                            }
                            else
                            {
                                logger.Error("Could not resolve decryption method!");
                            }
                        }
                        else
                        {
                            logger.Info("Small value (likely index/counter)");
                            // Try simple XOR for small values
                            TrySimpleXOR(encryptedValue, instructions, i, logger);
                        }
                    }
                }
            }
            
            logger.Info($"");
            logger.Info($"=== SUMMARY ===");
            logger.Info($"Total calls found: {totalCalls}");
            logger.Info($"Large values (potential strings): {largeValues}");
            logger.Info($"Strings decrypted: {DecryptedStrings}");
        }
        
        private static void TrySimpleXOR(int encrypted, IList<Instruction> instructions, int index, Utils.ILogger logger)
        {
            int[] keys = { 0x2A, 0x7F, 0xFF, 0x2D, 0x5A, 0xA5 };
            
            foreach (var key in keys)
            {
                int test = encrypted ^ key;
                if (test >= 32 && test <= 126) // Printable ASCII
                {
                    string decrypted = new string((char)test, 1);
                    
                    instructions[index - 1].OpCode = OpCodes.Nop;
                    instructions[index].OpCode = OpCodes.Ldstr;
                    instructions[index].Operand = decrypted;
                    
                    DecryptedStrings++;
                    logger.Success($"Small XOR {key:X}: '{decrypted}'");
                    return;
                }
            }
        }
        
        private static void AnalyzeDecryptionMethod(int encrypted, MethodDef method, Utils.ILogger logger)
        {
            var instr = method.Body.Instructions;
            
            logger.Info("=== ALGORITHM ANALYSIS ===");
            
            // Check for common patterns
            bool hasLdarg0 = false;
            bool hasLdcI4 = false;
            int ldcValue = 0;
            Code? operation = null;
            
            foreach (var il in instr)
            {
                logger.Info($"  Analyzing: {il.OpCode} {il.Operand}");
                
                if (il.OpCode == OpCodes.Ldarg_0)
                    hasLdarg0 = true;
                else if (il.IsLdcI4())
                {
                    hasLdcI4 = true;
                    ldcValue = il.GetLdcI4Value();
                }
                else if (il.OpCode.Code == Code.Xor || 
                         il.OpCode.Code == Code.Add || 
                         il.OpCode.Code == Code.Sub ||
                         il.OpCode.Code == Code.Mul ||
                         il.OpCode.Code == Code.Div)
                {
                    operation = il.OpCode.Code;
                }
            }
            
            // Report findings
            if (hasLdarg0 && hasLdcI4 && operation.HasValue)
            {
                logger.Warning($"PATTERN FOUND: ldarg.0, ldc.i4 {ldcValue} (0x{ldcValue:X}), {operation}");
                
                // Try to decrypt using this pattern
                int result = operation.Value switch
                {
                    Code.Xor => encrypted ^ ldcValue,
                    Code.Add => encrypted + ldcValue,
                    Code.Sub => encrypted - ldcValue,
                    Code.Mul => encrypted * ldcValue,
                    Code.Div => encrypted / ldcValue,
                    _ => 0
                };
                
                // Try to decode as string
                TryDecodeAsString(result, logger);
            }
            else
            {
                logger.Error("Unknown pattern - need manual analysis");
            }
        }
        
        private static void TryDecodeAsString(int value, Utils.ILogger logger)
        {
            // Try as 4-byte string (ASCII)
            byte[] bytes = BitConverter.GetBytes(value);
            
            // Try little-endian
            string asciiLE = Encoding.ASCII.GetString(bytes).Trim('\0');
            if (IsReadableString(asciiLE))
            {
                logger.Success($"ASCII (LE): '{asciiLE}'");
                return;
            }
            
            // Try big-endian
            Array.Reverse(bytes);
            string asciiBE = Encoding.ASCII.GetString(bytes).Trim('\0');
            if (IsReadableString(asciiBE))
            {
                logger.Success($"ASCII (BE): '{asciiBE}'");
                return;
            }
            
            // Try UTF-16
            string unicode = Encoding.Unicode.GetString(BitConverter.GetBytes(value)).Trim('\0');
            if (IsReadableString(unicode))
            {
                logger.Success($"Unicode: '{unicode}'");
                return;
            }
            
            logger.Info($"Cannot decode 0x{value:X8} as string");
        }
        
        private static bool IsReadableString(string str)
        {
            if (string.IsNullOrEmpty(str)) return false;
            if (str.Length > 10) return false; // Too long for 4-byte int
            
            foreach (char c in str)
            {
                if (char.IsControl(c) && c != '\n' && c != '\r' && c != '\t')
                    return false;
            }
            
            return true;
        }
    }
}
