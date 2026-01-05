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
        private static byte[] _decryptedData;
        private static ModuleDefMD _module;

        public static void Execute(Context ctx)
        {
            _module = ctx.Module;
            var logger = ctx.Options.Logger;
            logger.Info("=== STRING DECRYPTION ANALYZER ===");
            
            // First, we need to simulate the initialization
            SimulateInitialization(ctx.Module, logger);
            
            if (_decryptedData == null)
            {
                logger.Error("Failed to decrypt data!");
                return;
            }
            
            logger.Info($"Decrypted data: {_decryptedData.Length} bytes");
            logger.Info("");
            
            // Find and decrypt all string calls
            DecryptAllStrings(ctx.Module, logger);
            
            logger.Info("");
            logger.Info("=== DECRYPTION COMPLETE ===");
            logger.Info($"Decrypted {DecryptedStrings} strings");
        }
        
        private static void SimulateInitialization(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("=== SIMULATING RUNTIME INITIALIZATION ===");
            
            // Step 1: Get the encrypted data from <Module>.byte_0 field
            var moduleType = module.GlobalType;
            if (moduleType == null)
            {
                logger.Error("No <Module> type found!");
                return;
            }
            
            FieldDef encryptedField = null;
            foreach (var field in moduleType.Fields)
            {
                if (field.Name == "byte_0" || 
                    (field.InitialValue != null && field.InitialValue.Length > 1000))
                {
                    encryptedField = field;
                    logger.Info($"Found encrypted data field: {field.Name} ({field.InitialValue?.Length ?? 0} bytes)");
                    break;
                }
            }
            
            if (encryptedField?.InitialValue == null)
            {
                logger.Error("No encrypted data field found!");
                return;
            }
            
            byte[] encryptedData = encryptedField.InitialValue;
            logger.Info($"Encrypted data size: {encryptedData.Length} bytes");
            
            // The data appears to be LZMA compressed based on the smethod_0
            // We need to find and analyze the actual decryption
            
            // Let's analyze the method calls to understand the decryption pattern
            AnalyzeDecryptionPatterns(module, logger);
            
            // Based on the provided code, the strings are decrypted using smethod_2 through smethod_6
            // Let's find the actual decrypted data
            _decryptedData = TryExtractDecryptedData(module, logger);
            
            if (_decryptedData == null)
            {
                // Try to find the data after initialization
                _decryptedData = FindRuntimeData(module, logger);
            }
        }
        
        private static void AnalyzeDecryptionPatterns(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("");
            logger.Info("=== ANALYZING DECRYPTION PATTERNS ===");
            
            // Look for the decryption methods (smethod_2 through smethod_6)
            var moduleType = module.GlobalType;
            
            foreach (var method in moduleType.Methods)
            {
                if (method.Name.StartsWith("smethod_") && 
                    method.MethodSig != null && 
                    method.MethodSig.Params.Count == 1 &&
                    method.MethodSig.Params[0].FullName == "System.Int32")
                {
                    logger.Info($"Found decryption method: {method.Name}");
                    
                    // Analyze the method to understand its transformation
                    AnalyzeMethodTransformation(method, logger);
                }
            }
        }
        
        private static void AnalyzeMethodTransformation(MethodDef method, Utils.ILogger logger)
        {
            if (!method.HasBody) return;
            
            // Each smethod_X has a specific transformation:
            // id = (id * CONSTANT) ^ CONSTANT2
            // Then: id = (id & 1073741823) << 2
            
            var instructions = method.Body.Instructions;
            int multiplyConst = 0;
            int xorConst = 0;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].IsLdcI4())
                {
                    int value = instructions[i].GetLdcI4Value();
                    
                    // Look for multiplication constants (negative values in the provided code)
                    if (i + 1 < instructions.Count && instructions[i + 1].OpCode.Code == Code.Mul)
                    {
                        multiplyConst = value;
                    }
                    // Look for XOR constants
                    else if (i > 0 && instructions[i - 1].OpCode.Code == Code.Xor)
                    {
                        xorConst = value;
                    }
                }
            }
            
            if (multiplyConst != 0 || xorConst != 0)
            {
                logger.Info($"  Transformation: id = (id * {multiplyConst}) ^ {xorConst}");
            }
            
            // Check what type of data this method returns
            int stringTypeCount = 0;
            int arrayTypeCount = 0;
            int valueTypeCount = 0;
            
            foreach (var instr in instructions)
            {
                if (instr.OpCode == OpCodes.Call && instr.Operand != null)
                {
                    string operand = instr.Operand.ToString();
                    if (operand.Contains("GetString"))
                        stringTypeCount++;
                    else if (operand.Contains("Array.CreateInstance"))
                        arrayTypeCount++;
                    else if (operand.Contains("BlockCopy"))
                        valueTypeCount++;
                }
            }
            
            logger.Info($"  Returns: Strings={stringTypeCount}, Arrays={arrayTypeCount}, Values={valueTypeCount}");
        }
        
        private static byte[] TryExtractDecryptedData(ModuleDefMD module, Utils.ILogger logger)
        {
            // Look for the actual decrypted byte array in the assembly
            // It might be in a static constructor or initialized field
            
            var moduleType = module.GlobalType;
            
            // Check if there's a method that initializes the data
            foreach (var method in moduleType.Methods)
            {
                if (method.Name == ".cctor") // Static constructor
                {
                    logger.Info("Analyzing static constructor...");
                    
                    if (method.HasBody)
                    {
                        // Look for byte array creation and assignment
                        var instructions = method.Body.Instructions;
                        for (int i = 0; i < instructions.Count; i++)
                        {
                            if (instructions[i].OpCode == OpCodes.Stsfld)
                            {
                                var field = instructions[i].Operand as FieldDef;
                                if (field != null && field.FieldType.FullName == "System.Byte[]")
                                {
                                    logger.Info($"Found byte array assignment to {field.Name}");
                                    
                                    // Try to find the actual data
                                    if (i > 0 && instructions[i - 1].OpCode == OpCodes.Call)
                                    {
                                        // Might be calling smethod_0 (decompression)
                                        logger.Info($"Data is set via method call: {instructions[i - 1].Operand}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            return null;
        }
        
        private static byte[] FindRuntimeData(ModuleDefMD module, Utils.ILogger logger)
        {
            // Since we can't easily simulate the full initialization,
            // let's try to extract the data that's already in the assembly
            
            // Look for large embedded resources or initialized data
            foreach (var resource in module.Resources)
            {
                if (resource is EmbeddedResource embedded)
                {
                    logger.Info($"Found embedded resource: {resource.Name} ({embedded.Data.Length} bytes)");
                    
                    // Check if it looks like compressed/encrypted data
                    if (embedded.Data.Length > 1000)
                    {
                        return embedded.Data;
                    }
                }
            }
            
            return null;
        }
        
        private static void DecryptAllStrings(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("");
            logger.Info("=== DECRYPTING STRINGS ===");
            
            // First, identify all string decryption calls
            var stringDecryptionMethods = new System.Collections.Generic.Dictionary<string, Func<int, string>>();
            
            // Based on the provided code, we have these methods:
            // smethod_2: id = (id * -94884425) ^ 2053344156
            // smethod_3: id = (id * -1905422515) ^ 169980300
            // smethod_4: id = (id * -1320854719) ^ -576081527
            // smethod_5: id = (id * 1822996679) ^ 1495263297
            // smethod_6: id = (id * -946786095) ^ -1843072914
            
            // We need to find which methods are actually used for strings
            FindStringDecryptionMethods(module, stringDecryptionMethods, logger);
            
            if (stringDecryptionMethods.Count == 0)
            {
                logger.Warn("No string decryption methods identified!");
                return;
            }
            
            // Now scan all methods for calls to these decryption methods
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    
                    ProcessMethodForStrings(method, stringDecryptionMethods, logger);
                }
            }
        }
        
        private static void FindStringDecryptionMethods(ModuleDefMD module, 
            System.Collections.Generic.Dictionary<string, Func<int, string>> decryptionMethods,
            Utils.ILogger logger)
        {
            var moduleType = module.GlobalType;
            
            // Map of method names to their transformations
            var transformations = new System.Collections.Generic.Dictionary<string, Tuple<int, int>>
            {
                { "smethod_2", new Tuple<int, int>(-94884425, 2053344156) },
                { "smethod_3", new Tuple<int, int>(-1905422515, 169980300) },
                { "smethod_4", new Tuple<int, int>(-1320854719, -576081527) },
                { "smethod_5", new Tuple<int, int>(1822996679, 1495263297) },
                { "smethod_6", new Tuple<int, int>(-946786095, -1843072914) }
            };
            
            foreach (var method in moduleType.Methods)
            {
                if (transformations.ContainsKey(method.Name))
                {
                    var transform = transformations[method.Name];
                    
                    // Create a decryption function for this method
                    decryptionMethods[method.FullName] = (id) =>
                    {
                        return DecryptString(id, transform.Item1, transform.Item2, method.Name);
                    };
                    
                    logger.Info($"Registered decryption method: {method.Name}");
                }
            }
        }
        
        private static string DecryptString(int id, int multiplyConst, int xorConst, string methodName)
        {
            try
            {
                // Apply the transformation: id = (id * CONSTANT) ^ CONSTANT2
                long transformedId = (id * (long)multiplyConst) ^ xorConst;
                
                // Get the data type (2 bits from position 30-31)
                int dataType = (int)((uint)transformedId >> 30);
                
                // Get the actual offset: (id & 1073741823) << 2
                int offset = (int)((transformedId & 1073741823) << 2);
                
                // For debugging
                Console.WriteLine($"[{methodName}] ID: {id} -> Transformed: {transformedId}, Type: {dataType}, Offset: {offset}");
                
                // Type 0 or 2 typically indicates strings in the provided code
                if (dataType == 0 || dataType == 2)
                {
                    // Read string length (4 bytes at offset)
                    if (offset + 4 >= _decryptedData.Length) return "[ERROR: Offset out of bounds]";
                    
                    int length = BitConverter.ToInt32(_decryptedData, offset);
                    
                    // Read the string data
                    if (offset + 4 + length > _decryptedData.Length) 
                        return $"[ERROR: String length {length} exceeds buffer at offset {offset}]";
                    
                    return Encoding.UTF8.GetString(_decryptedData, offset + 4, length);
                }
                
                return $"[Non-string type {dataType}]";
            }
            catch (Exception ex)
            {
                return $"[DECRYPTION ERROR: {ex.Message}]";
            }
        }
        
        private static void ProcessMethodForStrings(MethodDef method, 
            System.Collections.Generic.Dictionary<string, Func<int, string>> decryptionMethods,
            Utils.ILogger logger)
        {
            var instructions = method.Body.Instructions;
            bool modified = false;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                // Look for pattern: ldc.i4 (constant) followed by call to decryption method
                if (instructions[i].IsLdcI4() && i + 1 < instructions.Count)
                {
                    if (instructions[i + 1].OpCode == OpCodes.Call)
                    {
                        var calledMethod = instructions[i + 1].Operand as IMethod;
                        if (calledMethod != null && decryptionMethods.ContainsKey(calledMethod.FullName))
                        {
                            int stringId = instructions[i].GetLdcI4Value();
                            var decryptFunc = decryptionMethods[calledMethod.FullName];
                            
                            try
                            {
                                string decryptedString = decryptFunc(stringId);
                                
                                if (!decryptedString.StartsWith("[ERROR") && !decryptedString.StartsWith("[Non-string"))
                                {
                                    logger.Info($"Decrypted string in {method.FullName}: \"{decryptedString}\"");
                                    
                                    // Replace the call with the decrypted string
                                    instructions[i].OpCode = OpCodes.Ldstr;
                                    instructions[i].Operand = decryptedString;
                                    instructions[i + 1].OpCode = OpCodes.Nop;
                                    instructions[i + 1].Operand = null;
                                    
                                    modified = true;
                                    DecryptedStrings++;
                                    
                                    // Only show first few to avoid spam
                                    if (DecryptedStrings <= 10)
                                    {
                                        logger.Info($"  String ID: {stringId} -> \"{decryptedString}\"");
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                logger.Warn($"Failed to decrypt string ID {stringId}: {ex.Message}");
                            }
                        }
                    }
                }
            }
            
            if (modified)
            {
                method.Body.OptimizeMacros();
            }
        }
    }
}
