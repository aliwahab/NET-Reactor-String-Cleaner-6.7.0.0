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
            logger.Info("=== CONFUSEREX STRING DECRYPTION ===");
            
            // STEP 1: Find the encrypted byte array
            byte[] encryptedData = FindEncryptedByteArray(ctx.Module, logger);
            if (encryptedData == null)
            {
                logger.Error("CRITICAL: Could not find encrypted byte array!");
                logger.Info("Searching for alternative array...");
                DebugFindAllArrays(ctx.Module, logger);
                return;
            }
            
            logger.Success($"Found encrypted data: {encryptedData.Length} bytes");
            
            // STEP 2: Process all string decryption calls
            int processed = 0;
            
            foreach (var typeDef in ctx.Module.GetTypes().Where(x => x.HasMethods))
            foreach (var methodDef in typeDef.Methods.Where(x => x.HasBody)) 
            {
                var instructions = methodDef.Body.Instructions;
                
                for (int i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i].OpCode == OpCodes.Call && 
                        instructions[i].Operand is IMethod decMethod &&
                        i > 0 && instructions[i - 1].IsLdcI4())
                    {
                        processed++;
                        int index = instructions[i - 1].GetLdcI4Value();
                        
                        // Only process if it's likely a real string (not small index)
                        if (Math.Abs(index) > 1000 || index < 0)
                        {
                            try
                            {
                                string decrypted = DecryptConfuserExString(index, encryptedData);
                                
                                if (decrypted != null && decrypted.Length > 0)
                                {
                                    // Replace: ldc.i4 VALUE -> call DECRYPTION
                                    // With:    nop         -> ldstr "DECRYPTED"
                                    instructions[i - 1].OpCode = OpCodes.Nop;
                                    instructions[i].OpCode = OpCodes.Ldstr;
                                    instructions[i].Operand = decrypted;
                                    
                                    DecryptedStrings++;
                                    
                                    // Log interesting strings
                                    if (decrypted.Length > 1)
                                    {
                                        string preview = decrypted.Length > 50 ? 
                                            decrypted.Substring(0, 47) + "..." : decrypted;
                                        logger.Success($"[{index}] '{preview}'");
                                    }
                                }
                                else
                                {
                                    logger.Warning($"[{index}] Failed to decrypt");
                                }
                            }
                            catch (Exception ex)
                            {
                                logger.Error($"[{index}] Error: {ex.Message}");
                            }
                        }
                        else
                        {
                            // Small values - try simple XOR for array indices
                            TryDecryptSmallValue(index, instructions, i, logger);
                        }
                    }
                }
            }
            
            logger.Info($"");
            logger.Info($"=== PROCESSING COMPLETE ===");
            logger.Info($"Total calls processed: {processed}");
            logger.Info($"Strings decrypted: {DecryptedStrings}");
        }
        
        private static byte[] FindEncryptedByteArray(ModuleDefMD module, Utils.ILogger logger)
        {
            // Method 1: Look in <Module> class (most common)
            var moduleType = module.GlobalType;
            if (moduleType != null)
            {
                foreach (var field in moduleType.Fields)
                {
                    if (field.FieldType.FullName == "System.Byte[]" && 
                        field.IsStatic && 
                        field.InitialValue != null &&
                        field.InitialValue.Length > 1024) // Should be large
                    {
                        logger.Info($"Found in <Module>: {field.Name} ({field.InitialValue.Length} bytes)");
                        return field.InitialValue;
                    }
                }
            }
            
            // Method 2: Search all types
            foreach (var type in module.GetTypes())
            {
                foreach (var field in type.Fields)
                {
                    if (field.FieldType.FullName == "System.Byte[]" && 
                        field.IsStatic && 
                        field.InitialValue != null)
                    {
                        // Check if it looks like string data (has null bytes, printable chars)
                        int printable = 0;
                        foreach (byte b in field.InitialValue)
                        {
                            if (b >= 32 && b <= 126 || b == 0) printable++;
                        }
                        
                        if (printable > field.InitialValue.Length * 0.3) // 30% printable
                        {
                            logger.Info($"Candidate: {type.Name}.{field.Name} ({field.InitialValue.Length} bytes)");
                            return field.InitialValue;
                        }
                    }
                }
            }
            
            return null;
        }
        
        private static string DecryptConfuserExString(int index, byte[] data)
        {
            // Handle negative indices (common in ConfuserEx)
            if (index < 0)
                index = data.Length + index; // Convert to positive offset from end
            
            // Check bounds
            if (index < 0 || index + 4 >= data.Length)
                return $"[ERROR: Index {index} out of bounds]";
            
            try
            {
                // Read 4-byte length (little-endian) as discovered in IL
                int length = data[index] | 
                            (data[index + 1] << 8) | 
                            (data[index + 2] << 16) | 
                            (data[index + 3] << 24);
                
                // Validate length
                if (length <= 0 || length > 65536) // Reasonable string limit
                    return $"[ERROR: Invalid length {length}]";
                
                if (index + 4 + length > data.Length)
                    return $"[ERROR: Length {length} exceeds array bounds]";
                
                // Decode as UTF8
                string result = Encoding.UTF8.GetString(data, index + 4, length);
                
                // Clean up null characters
                result = result.Replace("\0", "");
                
                return result;
            }
            catch
            {
                return null;
            }
        }
        
        private static void TryDecryptSmallValue(int value, IList<Instruction> instructions, int index, Utils.ILogger logger)
        {
            // Small values are likely array indices or simple XOR
            int[] keys = { 0x2A, 0x7F, 0xFF, 0x2D };
            
            foreach (var key in keys)
            {
                int test = value ^ key;
                if (test >= 32 && test <= 126) // Printable ASCII
                {
                    string decrypted = new string((char)test, 1);
                    
                    instructions[index - 1].OpCode = OpCodes.Nop;
                    instructions[index].OpCode = OpCodes.Ldstr;
                    instructions[index].Operand = decrypted;
                    
                    DecryptedStrings++;
                    return;
                }
            }
        }
        
        private static void DebugFindAllArrays(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("=== ALL BYTE ARRAYS IN MODULE ===");
            
            int arrayCount = 0;
            
            foreach (var type in module.GetTypes())
            {
                foreach (var field in type.Fields)
                {
                    if (field.FieldType.FullName == "System.Byte[]")
                    {
                        arrayCount++;
                        logger.Info($"#{arrayCount}: {type.Name}.{field.Name}");
                        
                        if (field.InitialValue != null)
                        {
                            logger.Info($"  Size: {field.InitialValue.Length} bytes");
                            
                            // Show first 32 bytes as hex
                            int showBytes = Math.Min(32, field.InitialValue.Length);
                            StringBuilder hex = new StringBuilder();
                            for (int i = 0; i < showBytes; i++)
                            {
                                hex.Append($"{field.InitialValue[i]:X2} ");
                                if ((i + 1) % 16 == 0) hex.AppendLine();
                            }
                            logger.Info($"  Hex: {hex}");
                            
                            // Try to detect if it's string data
                            int nulls = field.InitialValue.Count(b => b == 0);
                            int printables = field.InitialValue.Count(b => b >= 32 && b <= 126);
                            logger.Info($"  Stats: {nulls} nulls, {printables} printables");
                        }
                    }
                }
            }
            
            logger.Info($"Total byte arrays found: {arrayCount}");
        }
    }
}
