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
            logger.Info("=== SIMPLE STRING REPLACEMENT ===");
            
            // Get the string data array
            byte[] stringData = GetStringData(ctx.Module);
            if (stringData == null)
            {
                logger.Error("No string data!");
                return;
            }
            
            logger.Info($"String data: {stringData.Length} bytes");
            
            // Try to brute force decrypt the data
            byte[] decryptedData = BruteForceDecrypt(stringData, logger);
            
            if (decryptedData != null)
            {
                logger.Success($"Successfully decrypted data!");
                ProcessAllCalls(ctx.Module, decryptedData, logger);
            }
            else
            {
                logger.Error("Could not decrypt data. Manual analysis needed.");
            }
            
            logger.Success($"Decrypted {DecryptedStrings} strings!");
        }
        
        private static byte[] GetStringData(ModuleDefMD module)
        {
            // Get <Module> type
            var moduleType = module.GlobalType;
            if (moduleType == null) return null;
            
            // Find first non-empty static initial value
            foreach (var field in moduleType.Fields)
            {
                try
                {
                    if (field.InitialValue != null && field.InitialValue.Length > 0)
                    {
                        return field.InitialValue;
                    }
                }
                catch { }
            }
            
            return null;
        }
        
        private static byte[] BruteForceDecrypt(byte[] data, Utils.ILogger logger)
        {
            logger.Info("Trying to decrypt data...");
            
            // Try XOR with all possible single-byte keys
            for (int key = 0; key < 256; key++)
            {
                byte[] test = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                {
                    test[i] = (byte)(data[i] ^ key);
                }
                
                // Check if this produces readable strings
                if (HasReadableContent(test))
                {
                    logger.Success($"Found XOR key: 0x{key:X2} ({key})");
                    return test;
                }
            }
            
            // Try ADD/SUB with common values
            int[] adjustments = { 1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97 };
            
            foreach (int adj in adjustments)
            {
                // Try ADD
                byte[] testAdd = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                {
                    testAdd[i] = (byte)((data[i] + adj) & 0xFF);
                }
                
                if (HasReadableContent(testAdd))
                {
                    logger.Success($"Found ADD key: {adj}");
                    return testAdd;
                }
                
                // Try SUB
                byte[] testSub = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                {
                    testSub[i] = (byte)((data[i] - adj) & 0xFF);
                }
                
                if (HasReadableContent(testSub))
                {
                    logger.Success($"Found SUB key: {adj}");
                    return testSub;
                }
            }
            
            return null;
        }
        
        private static bool HasReadableContent(byte[] data)
        {
            // Check first 100 bytes for printable ASCII
            int printable = 0;
            int total = Math.Min(100, data.Length);
            
            for (int i = 0; i < total; i++)
            {
                byte b = data[i];
                if (b >= 32 && b <= 126) // Printable ASCII
                    printable++;
                else if (b == 0 || b == 9 || b == 10 || b == 13) // Common whitespace
                    printable++;
            }
            
            // If more than 70% is printable, it's likely text
            return (printable * 100 / total) > 70;
        }
        
        private static void ProcessAllCalls(ModuleDefMD module, byte[] stringData, Utils.ILogger logger)
        {
            int totalCalls = 0;
            
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (method.HasBody)
                    {
                        totalCalls += ProcessMethod(method, stringData, logger);
                    }
                }
            }
            
            logger.Info($"Processed {totalCalls} string calls");
        }
        
        private static int ProcessMethod(MethodDef method, byte[] stringData, Utils.ILogger logger)
        {
            int processed = 0;
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Call && i > 0 && instructions[i - 1].IsLdcI4())
                {
                    int index = instructions[i - 1].GetLdcI4Value();
                    
                    if (Math.Abs(index) > 1000) // Likely string index
                    {
                        processed++;
                        
                        // Try to get string from data
                        string decrypted = GetStringFromData(index, stringData);
                        
                        if (!string.IsNullOrEmpty(decrypted))
                        {
                            // Replace the call
                            instructions[i - 1].OpCode = OpCodes.Nop;
                            instructions[i].OpCode = OpCodes.Ldstr;
                            instructions[i].Operand = decrypted;
                            
                            DecryptedStrings++;
                            
                            // Log it
                            string preview = decrypted.Length > 30 ? 
                                decrypted.Substring(0, 27) + "..." : decrypted;
                            logger.Success($"'{preview}'");
                        }
                    }
                }
            }
            
            return processed;
        }
        
        private static string GetStringFromData(int index, byte[] data)
        {
            try
            {
                // Try different interpretations of the index
                
                // 1. Direct offset
                if (index >= 0 && index < data.Length)
                {
                    string result = ReadStringAtOffset(data, index);
                    if (result != null) return result;
                }
                
                // 2. Negative = offset from end
                if (index < 0)
                {
                    int positive = data.Length + index;
                    if (positive >= 0 && positive < data.Length)
                    {
                        string result = ReadStringAtOffset(data, positive);
                        if (result != null) return result;
                    }
                }
                
                // 3. index * 4 (common in obfuscators)
                long byteOffset = (long)index * 4L;
                if (byteOffset < 0) byteOffset = data.Length + byteOffset;
                
                if (byteOffset >= 0 && byteOffset < data.Length)
                {
                    string result = ReadStringAtOffset(data, (int)byteOffset);
                    if (result != null) return result;
                }
                
                // 4. Try XOR with common keys
                int[] xorKeys = { 0x2A, 0x7F, 0xFF, 0x100, 0x55555555 };
                
                foreach (int key in xorKeys)
                {
                    int decoded = index ^ key;
                    
                    if (decoded >= 0 && decoded < data.Length)
                    {
                        string result = ReadStringAtOffset(data, decoded);
                        if (result != null) return result;
                    }
                }
            }
            catch { }
            
            return null;
        }
        
        private static string ReadStringAtOffset(byte[] data, int offset)
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
                        return Encoding.UTF8.GetString(data, offset + 4, length);
                    }
                }
                
                // Try null-terminated
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
            }
            catch { }
            
            return null;
        }
    }
}
