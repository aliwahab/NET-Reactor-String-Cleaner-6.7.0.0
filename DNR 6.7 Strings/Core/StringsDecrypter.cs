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
            logger.Info("=== STRING DECRYPTION ===");
            
            // STEP 1: Get string data from <Module>
            byte[] stringData = GetModuleStringData(ctx.Module);
            if (stringData == null)
            {
                logger.Error("No string data found!");
                return;
            }
            
            logger.Info($"String data: {stringData.Length} bytes");
            
            // STEP 2: Process all methods for string calls
            ProcessAllMethods(ctx.Module, stringData, logger);
            
            logger.Success($"Decrypted {DecryptedStrings} strings!");
        }
        
        private static byte[] GetModuleStringData(ModuleDefMD module)
        {
            var moduleType = module.GlobalType;
            if (moduleType == null) return null;
            
            foreach (var field in moduleType.Fields)
            {
                if (field.IsStatic && field.InitialValue != null && field.InitialValue.Length > 0)
                {
                    return field.InitialValue;
                }
            }
            
            return null;
        }
        
        private static void ProcessAllMethods(ModuleDefMD module, byte[] stringData, Utils.ILogger logger)
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
            int callsInMethod = 0;
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Call && i > 0 && instructions[i - 1].IsLdcI4())
                {
                    int index = instructions[i - 1].GetLdcI4Value();
                    
                    // Large values are likely string indices
                    if (Math.Abs(index) > 1000)
                    {
                        callsInMethod++;
                        
                        // Try to decrypt
                        string decrypted = DecryptString(index, stringData);
                        
                        if (!string.IsNullOrEmpty(decrypted))
                        {
                            // Replace the call with the string
                            instructions[i - 1].OpCode = OpCodes.Nop;
                            instructions[i].OpCode = OpCodes.Ldstr;
                            instructions[i].Operand = decrypted;
                            
                            DecryptedStrings++;
                            
                            // Log it
                            string preview = decrypted.Length > 30 ? 
                                decrypted.Substring(0, 27) + "..." : decrypted;
                            logger.Success($"'{preview}'");
                        }
                        else
                        {
                            // Log failed attempts
                            logger.Info($"Failed index: {index}");
                        }
                    }
                }
            }
            
            return callsInMethod;
        }
        
        private static string DecryptString(int index, byte[] data)
        {
            try
            {
                // METHOD 1: Try as direct byte offset
                if (index >= 0 && index < data.Length)
                {
                    string result = ReadStringFromData(data, index);
                    if (result != null) return result;
                }
                
                // METHOD 2: Try negative as offset from end
                if (index < 0)
                {
                    int positiveIndex = data.Length + index;
                    if (positiveIndex >= 0 && positiveIndex < data.Length)
                    {
                        string result = ReadStringFromData(data, positiveIndex);
                        if (result != null) return result;
                    }
                }
                
                // METHOD 3: Try index * 4 (common in ConfuserEx)
                long byteOffset = (long)index * 4L;
                
                // Handle negative/overflow
                if (byteOffset < 0)
                {
                    byteOffset = data.Length + byteOffset;
                }
                
                if (byteOffset >= 0 && byteOffset < data.Length)
                {
                    string result = ReadStringFromData(data, (int)byteOffset);
                    if (result != null) return result;
                }
                
                // METHOD 4: Try XOR with common keys
                int[] xorKeys = { 0x2A, 0x7F, 0xFF, 0x100, 0x2D, 0x5A, 0xA5 };
                
                foreach (int key in xorKeys)
                {
                    int decoded = index ^ key;
                    
                    // Try as positive offset
                    if (decoded >= 0 && decoded < data.Length)
                    {
                        string result = ReadStringFromData(data, decoded);
                        if (result != null) return result;
                    }
                    
                    // Try as negative offset
                    if (decoded < 0)
                    {
                        int positive = data.Length + decoded;
                        if (positive >= 0 && positive < data.Length)
                        {
                            string result = ReadStringFromData(data, positive);
                            if (result != null) return result;
                        }
                    }
                }
            }
            catch
            {
                return null;
            }
            
            return null;
        }
        
        private static string ReadStringFromData(byte[] data, int offset)
        {
            if (offset < 0 || offset >= data.Length) return null;
            
            try
            {
                // Pattern 1: 4-byte length + UTF8 string
                if (offset + 4 <= data.Length)
                {
                    // FIXED: Use BitConverter to avoid uint/int issues
                    int length = BitConverter.ToInt32(data, offset);
                    
                    if (length > 0 && length < 1000 && offset + 4 + length <= data.Length)
                    {
                        string result = Encoding.UTF8.GetString(data, offset + 4, length);
                        return CleanString(result);
                    }
                }
                
                // Pattern 2: Null-terminated string
                for (int i = offset; i < data.Length; i++)
                {
                    if (data[i] == 0)
                    {
                        int length = i - offset;
                        if (length > 0)
                        {
                            string result = Encoding.UTF8.GetString(data, offset, length);
                            return CleanString(result);
                        }
                        break;
                    }
                }
                
                // Pattern 3: Try to read as ASCII until null
                int maxLength = Math.Min(100, data.Length - offset);
                string ascii = Encoding.ASCII.GetString(data, offset, maxLength);
                ascii = ascii.Split('\0')[0];
                
                if (ascii.Length > 0 && IsPrintable(ascii))
                {
                    return ascii;
                }
            }
            catch
            {
                return null;
            }
            
            return null;
        }
        
        private static string CleanString(string str)
        {
            if (string.IsNullOrEmpty(str)) return str;
            
            var cleaned = new StringBuilder();
            foreach (char c in str)
            {
                if (c == '\0') continue;
                if (char.IsControl(c) && c != '\n' && c != '\r' && c != '\t')
                    continue;
                cleaned.Append(c);
            }
            
            return cleaned.ToString().Trim();
        }
        
        private static bool IsPrintable(string str)
        {
            foreach (char c in str)
            {
                if (c < 32 || c > 126) return false;
            }
            return true;
        }
    }
}
