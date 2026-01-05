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
            logger.Info("=== STRING DECRYPTION ANALYZER ===");
            
            // Get the encrypted data
            byte[] encryptedData = GetEncryptedData(ctx.Module);
            if (encryptedData == null)
            {
                logger.Error("No encrypted data found!");
                return;
            }
            
            logger.Info($"Encrypted data: {encryptedData.Length} bytes");
            logger.Info($"First 32 bytes (hex): {BitConverter.ToString(encryptedData, 0, Math.Min(32, encryptedData.Length))}");
            logger.Info("");
            
            // STEP 1: Analyze the data structure
            AnalyzeDataStructure(encryptedData, logger);
            
            // STEP 2: Find and analyze decryption methods
            FindDecryptionMethods(ctx.Module, logger);
            
            // STEP 3: Find all string calls
            FindStringCalls(ctx.Module, logger);
            
            logger.Info("");
            logger.Info("=== ANALYSIS COMPLETE ===");
            logger.Info($"Found string calls but need decryption algorithm.");
        }
        
        private static byte[] GetEncryptedData(ModuleDefMD module)
        {
            var moduleType = module.GlobalType;
            if (moduleType == null) return null;
            
            foreach (var field in moduleType.Fields)
            {
                if (field.InitialValue != null && field.InitialValue.Length > 0)
                {
                    return field.InitialValue;
                }
            }
            
            return null;
        }
        
        private static void AnalyzeDataStructure(byte[] data, Utils.ILogger logger)
        {
            logger.Info("=== DATA STRUCTURE ANALYSIS ===");
            
            // Count byte frequencies
            int[] freq = new int[256];
            foreach (byte b in data) freq[b]++;
            
            // Find most common bytes
            logger.Info("Most common bytes:");
            for (int i = 0; i < 10; i++)
            {
                int maxIndex = 0;
                int maxValue = 0;
                for (int j = 0; j < 256; j++)
                {
                    if (freq[j] > maxValue)
                    {
                        maxValue = freq[j];
                        maxIndex = j;
                    }
                }
                
                if (maxValue > 0)
                {
                    logger.Info($"  Byte 0x{maxIndex:X2} ({maxIndex}): {maxValue} times ({maxValue * 100 / data.Length}%)");
                    freq[maxIndex] = 0; // Remove for next iteration
                }
            }
            
            // Check for patterns that might indicate encryption type
            logger.Info("");
            logger.Info("Encryption analysis:");
            
            // If data is mostly high bytes, might be XOR encrypted
            int highBytes = data.Count(b => b > 127);
            logger.Info($"High bytes (>127): {highBytes} ({highBytes * 100 / data.Length}%)");
            
            // Check for common XOR patterns
            logger.Info("Testing common XOR patterns:");
            
            byte[] commonXorBytes = { 0x00, 0xFF, 0xAA, 0x55, 0x2A, 0x7F, 0x2D, 0x5A, 0xA5 };
            
            foreach (byte xorKey in commonXorBytes)
            {
                int printable = 0;
                for (int i = 0; i < Math.Min(100, data.Length); i++)
                {
                    byte decrypted = (byte)(data[i] ^ xorKey);
                    if (decrypted >= 32 && decrypted <= 126) printable++;
                }
                
                if (printable > 70) // More than 70% printable
                {
                    logger.Info($"  XOR 0x{xorKey:X2}: {printable}% printable - POSSIBLE");
                }
            }
        }
        
        private static void FindDecryptionMethods(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("");
            logger.Info("=== FINDING DECRYPTION METHODS ===");
            
            // Look in <Module> for methods that might decrypt strings
            var moduleType = module.GlobalType;
            if (moduleType == null) return;
            
            int methodCount = 0;
            
            foreach (var method in moduleType.Methods)
            {
                if (method.MethodSig != null && method.MethodSig.Params.Count == 1)
                {
                    var paramType = method.MethodSig.Params[0];
                    if (paramType.FullName == "System.Int32" || paramType.FullName == "System.UInt32")
                    {
                        methodCount++;
                        logger.Info($"");
                        logger.Info($"Method #{methodCount}: {method.Name}");
                        logger.Info($"Returns: {method.MethodSig.RetType.FullName}");
                        logger.Info($"Parameter: {paramType.FullName}");
                        
                        if (method.HasBody)
                        {
                            logger.Info("First 20 instructions:");
                            int instrCount = 0;
                            
                            foreach (var instr in method.Body.Instructions)
                            {
                                instrCount++;
                                string operand = instr.Operand?.ToString() ?? "";
                                
                                // Shorten long strings
                                if (operand.Length > 60)
                                    operand = operand.Substring(0, 57) + "...";
                                
                                logger.Info($"  {instr.OpCode} {operand}");
                                
                                if (instrCount >= 20)
                                {
                                    logger.Info($"  ... and {method.Body.Instructions.Count - 20} more");
                                    break;
                                }
                            }
                            
                            // Analyze what this method does
                            AnalyzeMethodLogic(method, logger);
                        }
                        
                        // Only show first 3 methods
                        if (methodCount >= 3) break;
                    }
                }
            }
            
            if (methodCount == 0)
            {
                logger.Info("No int-taking methods found in <Module>");
            }
        }
        
        private static void AnalyzeMethodLogic(MethodDef method, Utils.ILogger logger)
        {
            var instructions = method.Body.Instructions;
            
            // Look for patterns
            bool loadsByteArray = false;
            bool callsGetString = false;
            bool usesXor = false;
            bool usesMath = false;
            bool usesBitConverter = false;
            
            foreach (var instr in instructions)
            {
                if (instr.OpCode == OpCodes.Ldsfld)
                {
                    if (instr.Operand != null && instr.Operand.ToString().Contains("Byte[]"))
                    {
                        loadsByteArray = true;
                    }
                }
                else if (instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt)
                {
                    if (instr.Operand != null)
                    {
                        string operand = instr.Operand.ToString();
                        if (operand.Contains("GetString") || operand.Contains("Encoding"))
                        {
                            callsGetString = true;
                        }
                        else if (operand.Contains("Math.") || operand.Contains("BitConverter."))
                        {
                            usesMath = true;
                        }
                    }
                }
                else if (instr.OpCode.Code == Code.Xor)
                {
                    usesXor = true;
                }
            }
            
            logger.Info("Method analysis:");
            if (loadsByteArray) logger.Info("  - Loads a byte array");
            if (callsGetString) logger.Info("  - Calls string decoding methods");
            if (usesXor) logger.Info("  - Uses XOR operations");
            if (usesMath) logger.Info("  - Uses Math/BitConverter functions");
        }
        
        private static void FindStringCalls(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("");
            logger.Info("=== FINDING STRING CALLS ===");
            
            int callCount = 0;
            int uniqueIndices = 0;
            var seenIndices = new System.Collections.Generic.HashSet<int>();
            
            // Sample some string calls to understand pattern
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    
                    var instructions = method.Body.Instructions;
                    
                    for (int i = 0; i < instructions.Count; i++)
                    {
                        if (instructions[i].OpCode == OpCodes.Call && i > 0 && instructions[i - 1].IsLdcI4())
                        {
                            int index = instructions[i - 1].GetLdcI4Value();
                            
                            if (Math.Abs(index) > 1000)
                            {
                                callCount++;
                                
                                if (!seenIndices.Contains(index))
                                {
                                    seenIndices.Add(index);
                                    uniqueIndices++;
                                    
                                    // Log first 10 unique indices
                                    if (uniqueIndices <= 10)
                                    {
                                        var calledMethod = instructions[i].Operand as IMethod;
                                        string methodName = calledMethod?.FullName ?? "unknown";
                                        
                                        if (methodName.Length > 50)
                                            methodName = methodName.Substring(0, 47) + "...";
                                        
                                        logger.Info($"Index: {index} (0x{index:X8}) -> {methodName}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            logger.Info($"");
            logger.Info($"Found {callCount} total string calls");
            logger.Info($"Found {uniqueIndices} unique string indices");
            
            // Show index statistics
            if (seenIndices.Count > 0)
            {
                int min = seenIndices.Min();
                int max = seenIndices.Max();
                int avg = (int)seenIndices.Average();
                
                logger.Info($"Index range: {min} to {max}");
                logger.Info($"Average index: {avg}");
                
                // Count positive vs negative
                int positive = seenIndices.Count(i => i > 0);
                int negative = seenIndices.Count(i => i < 0);
                
                logger.Info($"Positive indices: {positive}, Negative indices: {negative}");
            }
        }
    }
}
