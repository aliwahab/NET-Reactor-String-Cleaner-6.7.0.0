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
        private static byte[] _decryptedStringData;

        public static void Execute(Context ctx)
        {
            var logger = ctx.Options.Logger;
            logger.Info("=== CONFUSEREX FINAL DECRYPTOR ===");
            
            // STEP 1: Get the encrypted string data
            byte[] encryptedData = GetEncryptedStringData(ctx.Module, logger);
            if (encryptedData == null)
            {
                logger.Error("No string data found!");
                return;
            }
            
            logger.Info($"Encrypted data: {encryptedData.Length} bytes");
            logger.Info($"First 16 bytes: {BitConverter.ToString(encryptedData, 0, Math.Min(16, encryptedData.Length))}");
            
            // STEP 2: Try to decrypt the data array
            _decryptedStringData = TryDecryptDataArray(encryptedData, ctx.Module, logger);
            
            if (_decryptedStringData == null)
            {
                logger.Error("Failed to decrypt string data!");
                logger.Info("Trying to find decryption method...");
                FindDecryptionMethod(ctx.Module, logger);
                return;
            }
            
            logger.Success($"Decrypted data: {_decryptedStringData.Length} bytes");
            
            // STEP 3: Now process string calls with decrypted data
            ProcessStringCalls(ctx.Module, logger);
            
            logger.Success($"Decrypted {DecryptedStrings} strings!");
        }
        
        private static byte[] GetEncryptedStringData(ModuleDefMD module, Utils.ILogger logger)
        {
            var moduleType = module.GlobalType;
            if (moduleType == null) return null;
            
            foreach (var field in moduleType.Fields)
            {
                if (field.IsStatic && field.InitialValue != null)
                {
                    return field.InitialValue;
                }
            }
            
            return null;
        }
        
        private static byte[] TryDecryptDataArray(byte[] encryptedData, ModuleDefMD module, Utils.ILogger logger)
        {
            // Try common ConfuserEx decryption patterns
            
            // PATTERN 1: Simple XOR with single byte key
            for (int key = 0; key < 256; key++)
            {
                byte[] decrypted = new byte[encryptedData.Length];
                for (int i = 0; i < encryptedData.Length; i++)
                {
                    decrypted[i] = (byte)(encryptedData[i] ^ key);
                }
                
                // Check if decrypted data contains readable strings
                if (ContainsReadableStrings(decrypted))
                {
                    logger.Success($"XOR key {key} (0x{key:X2}) worked!");
                    return decrypted;
                }
            }
            
            // PATTERN 2: XOR with rolling key
            int[] commonKeys = { 0x2A, 0x7F, 0xFF, 0x2D, 0x5A, 0xA5, 0x55, 0xAA };
            
            foreach (int key in commonKeys)
            {
                byte[] decrypted = new byte[encryptedData.Length];
                for (int i = 0; i < encryptedData.Length; i++)
                {
                    decrypted[i] = (byte)(encryptedData[i] ^ (key + i));
                }
                
                if (ContainsReadableStrings(decrypted))
                {
                    logger.Success($"Rolling XOR key 0x{key:X} worked!");
                    return decrypted;
                }
            }
            
            // PATTERN 3: Add/Subtract
            for (int key = 1; key < 256; key++)
            {
                byte[] decrypted = new byte[encryptedData.Length];
                for (int i = 0; i < encryptedData.Length; i++)
                {
                    decrypted[i] = (byte)((encryptedData[i] + key) & 0xFF);
                }
                
                if (ContainsReadableStrings(decrypted))
                {
                    logger.Success($"ADD key {key} worked!");
                    return decrypted;
                }
            }
            
            return null;
        }
        
        private static bool ContainsReadableStrings(byte[] data)
        {
            // Check if data contains readable UTF8 strings
            int stringCount = 0;
            
            for (int i = 0; i < data.Length - 4; i++)
            {
                // Look for 4-byte length followed by printable chars
                if (i + 4 < data.Length)
                {
                    int length = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);
                    
                    if (length > 0 && length < 100 && i + 4 + length < data.Length)
                    {
                        // Check if the string is readable
                        bool readable = true;
                        for (int j = 0; j < length; j++)
                        {
                            byte b = data[i + 4 + j];
                            if (b < 32 && b != 0 && b != 9 && b != 10 && b != 13) // Control chars
                            {
                                readable = false;
                                break;
                            }
                        }
                        
                        if (readable) stringCount++;
                        
                        // Skip this string
                        i += 4 + length - 1;
                    }
                }
            }
            
            return stringCount > 5; // At least 5 readable strings
        }
        
        private static void FindDecryptionMethod(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("=== SEARCHING FOR DECRYPTION METHOD ===");
            
            // Look for methods that might decrypt the byte array
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (method.MethodSig != null && method.HasBody)
                    {
                        // Check if method accesses the byte array
                        bool accessesByteArray = false;
                        
                        foreach (var instr in method.Body.Instructions)
                        {
                            if (instr.OpCode == OpCodes.Ldsfld && instr.Operand is IField field)
                            {
                                if (field.DeclaringType.FullName == "<Module>" && field.IsStatic)
                                {
                                    accessesByteArray = true;
                                    break;
                                }
                            }
                        }
                        
                        if (accessesByteArray)
                        {
                            logger.Info($"Found potential decryptor: {type.Name}.{method.Name}");
                            logger.Info("Method IL:");
                            
                            int count = 0;
                            foreach (var instr in method.Body.Instructions)
                            {
                                count++;
                                string operand = instr.Operand?.ToString() ?? "";
                                if (operand.Length > 50) operand = operand.Substring(0, 47) + "...";
                                logger.Info($"  {instr.OpCode} {operand}");
                                
                                if (count > 30)
                                {
                                    logger.Info($"  ... {method.Body.Instructions.Count - 30} more instructions");
                                    break;
                                }
                            }
                            
                            return; // Just show first one
                        }
                    }
                }
            }
        }
        
        private static void ProcessStringCalls(ModuleDefMD module, Utils.ILogger logger)
        {
            if (_decryptedStringData == null) return;
            
            int processed = 0;
            
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (method.HasBody)
                    {
                        processed += ProcessMethodCalls(method, logger);
                    }
                }
            }
            
            logger.Info($"Processed {processed} string calls");
        }
        
        private static int ProcessMethodCalls(MethodDef method, Utils.ILogger logger)
        {
            int callsProcessed = 0;
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Call && i > 0 && instructions[i - 1].IsLdcI4())
                {
                    int index = instructions[i - 1].GetLdcI4Value();
                    
                    if (Math.Abs(index) > 1000)
                    {
                        callsProcessed++;
                        
                        // Decrypt using decrypted data
                        string decrypted = DecryptStringFromData(index);
                        
                        if (!string.IsNullOrEmpty(decrypted))
                        {
                            // Replace the call
                            instructions[i - 1].OpCode = OpCodes.Nop;
                            instructions[i].OpCode = OpCodes.Ldstr;
                            instructions[i].Operand = decrypted;
                            
                            DecryptedStrings++;
                            
                            if (decrypted.Length > 1)
                            {
                                string preview = decrypted.Length > 30 ? 
                                    decrypted.Substring(0, 27) + "..." : decrypted;
                                logger.Success($"'{preview}'");
                            }
                        }
                    }
                }
            }
            
            return callsProcessed;
        }
        
        private static string DecryptStringFromData(int index)
        {
            if (_decryptedStringData == null) return null;
            
            try
            {
                // ConfuserEx: index is OFFSET / 4
                int byteOffset = index * 4;
                
                // Handle negative
                if (byteOffset < 0)
                {
                    byteOffset = _decryptedStringData.Length + byteOffset;
                }
                
                if (byteOffset < 0 || byteOffset >= _decryptedStringData.Length)
                {
                    return null;
                }
                
                // Read 4-byte length
                int length = _decryptedStringData[byteOffset] | 
                            (_decryptedStringData[byteOffset + 1] << 8) | 
                            (_decryptedStringData[byteOffset + 2] << 16) | 
                            (_decryptedStringData[byteOffset + 3] << 24);
                
                if (length > 0 && length < 10000 && byteOffset + 4 + length <= _decryptedStringData.Length)
                {
                    return Encoding.UTF8.GetString(_decryptedStringData, byteOffset + 4, length);
                }
            }
            catch { }
            
            return null;
        }
    }
}
