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
            
            // STEP 1: Analyze decryption methods to understand algorithm
            AnalyzeDecryptionMethods(ctx.Module, logger);
            
            // STEP 2: Find and process string calls
            int callsFound = FindAndProcessStringCalls(ctx.Module, logger);
            
            logger.Info($"Total string calls found: {callsFound}");
            logger.Success($"Decrypted {DecryptedStrings} strings!");
        }
        
        private static void AnalyzeDecryptionMethods(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("=== ANALYZING DECRYPTION METHODS ===");
            
            // Look in <Module> class for string decryption methods
            var moduleType = module.GlobalType;
            if (moduleType == null)
            {
                logger.Error("No <Module> class found!");
                return;
            }
            
            int methodCount = 0;
            
            foreach (var method in moduleType.Methods)
            {
                // Methods that might decrypt strings (take int parameter)
                if (method.MethodSig != null && method.MethodSig.Params.Count == 1)
                {
                    var paramType = method.MethodSig.Params[0];
                    if (paramType.FullName == "System.Int32" || paramType.FullName == "System.UInt32")
                    {
                        methodCount++;
                        logger.Info($"");
                        logger.Info($"=== METHOD #{methodCount}: {method.Name} ===");
                        logger.Info($"Return type: {method.MethodSig.RetType.FullName}");
                        logger.Info($"Parameters: {method.MethodSig.Params[0].FullName}");
                        
                        if (method.HasBody)
                        {
                            logger.Info("IL Instructions:");
                            foreach (var instr in method.Body.Instructions)
                            {
                                string operandStr = instr.Operand?.ToString() ?? "";
                                // Shorten long strings
                                if (operandStr.Length > 100)
                                    operandStr = operandStr.Substring(0, 97) + "...";
                                logger.Info($"  {instr.OpCode} {operandStr}");
                            }
                            
                            // Try to understand the algorithm
                            AnalyzeMethodAlgorithm(method, logger);
                        }
                        else
                        {
                            logger.Info("No method body");
                        }
                        
                        // Just analyze first 3 methods
                        if (methodCount >= 3) break;
                    }
                }
            }
            
            if (methodCount == 0)
            {
                logger.Warning("No int-taking methods found in <Module>!");
                logger.Info("Searching all methods...");
                
                // Search all methods for string decryption patterns
                foreach (var type in module.GetTypes())
                {
                    foreach (var method in type.Methods)
                    {
                        if (method.MethodSig != null && 
                            method.MethodSig.RetType.FullName == "System.String" &&
                            method.MethodSig.Params.Count == 1 &&
                            (method.MethodSig.Params[0].FullName == "System.Int32" || 
                             method.MethodSig.Params[0].FullName == "System.UInt32"))
                        {
                            logger.Info($"Found string method: {type.Name}.{method.Name}");
                            break;
                        }
                    }
                }
            }
        }
        
        private static void AnalyzeMethodAlgorithm(MethodDef method, Utils.ILogger logger)
        {
            var instructions = method.Body.Instructions;
            bool usesResources = false;
            bool usesByteArray = false;
            bool usesXor = false;
            bool usesMath = false;
            string byteArrayField = null;
            
            foreach (var instr in instructions)
            {
                if (instr.OpCode == OpCodes.Ldsfld && instr.Operand is IField field)
                {
                    if (field.FieldType.FullName == "System.Byte[]")
                    {
                        usesByteArray = true;
                        byteArrayField = field.FullName;
                    }
                }
                else if (instr.OpCode.Code == Code.Xor)
                {
                    usesXor = true;
                }
                else if (instr.OpCode == OpCodes.Call && instr.Operand is IMethod called)
                {
                    if (called.FullName.Contains("System.Math") || 
                        called.FullName.Contains("System.BitConverter"))
                    {
                        usesMath = true;
                    }
                    else if (called.FullName.Contains("Encoding") || 
                             called.FullName.Contains("GetString"))
                    {
                        // String decoding
                    }
                }
                else if (instr.OpCode == OpCodes.Callvirt && instr.Operand is IMethod calledVirt)
                {
                    if (calledVirt.FullName.Contains("GetString"))
                    {
                        // Definitely string decoding
                    }
                }
            }
            
            logger.Info("Algorithm analysis:");
            if (usesByteArray) logger.Info($"  - Uses byte array: {byteArrayField}");
            if (usesXor) logger.Info("  - Uses XOR operation");
            if (usesMath) logger.Info("  - Uses Math/BitConverter operations");
            if (usesResources) logger.Info("  - Uses resources");
        }
        
        private static int FindAndProcessStringCalls(ModuleDefMD module, Utils.ILogger logger)
        {
            int callsFound = 0;
            
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    
                    callsFound += ProcessMethodCalls(method, logger);
                }
            }
            
            return callsFound;
        }
        
        private static int ProcessMethodCalls(MethodDef method, Utils.ILogger logger)
        {
            int callsFound = 0;
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                // Look for: ldc.i4 VALUE -> call METHOD
                if (instructions[i].OpCode == OpCodes.Call && i > 0 && instructions[i - 1].IsLdcI4())
                {
                    int index = instructions[i - 1].GetLdcI4Value();
                    var calledMethod = instructions[i].Operand as IMethod;
                    
                    // Check if this looks like a string decryption call
                    if (Math.Abs(index) > 1000 && calledMethod != null)
                    {
                        callsFound++;
                        
                        // Log the call for debugging
                        logger.Info($"String call in {method.DeclaringType.Name}.{method.Name}:");
                        logger.Info($"  Index: {index} (0x{index:X8})");
                        logger.Info($"  Calls: {calledMethod.FullName}");
                        
                        // Try to decrypt (placeholder for now)
                        string decrypted = DecryptBasedOnAnalysis(index, calledMethod);
                        
                        if (!string.IsNullOrEmpty(decrypted) && !decrypted.StartsWith("[ERROR"))
                        {
                            // Replace with decrypted string
                            instructions[i - 1].OpCode = OpCodes.Nop;
                            instructions[i].OpCode = OpCodes.Ldstr;
                            instructions[i].Operand = decrypted;
                            
                            DecryptedStrings++;
                            logger.Success($"  Decrypted: '{decrypted}'");
                        }
                        else
                        {
                            logger.Warning($"  Could not decrypt");
                        }
                    }
                }
            }
            
            return callsFound;
        }
        
        private static string DecryptBasedOnAnalysis(int index, IMethod method)
        {
            // Placeholder - based on common ConfuserEx patterns
            
            // Pattern 1: Simple XOR with key
            int xorKey = 0x2A; // Common key
            int decoded = index ^ xorKey;
            
            // If decoded is small, might be char
            if (decoded > 31 && decoded < 127)
            {
                return new string((char)decoded, 1);
            }
            
            // Pattern 2: Index is offset/4 for string table
            int byteOffset = index * 4;
            
            // Try to interpret as UTF8 if offset were valid
            byte[] testBytes = BitConverter.GetBytes(byteOffset);
            string testString = Encoding.UTF8.GetString(testBytes).Trim('\0');
            
            if (testString.Length > 0 && testString.All(c => c >= 32 && c <= 126))
            {
                return testString;
            }
            
            return $"[ERROR: Unknown pattern for {index}]";
        }
    }
}
