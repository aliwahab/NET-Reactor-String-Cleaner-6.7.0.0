using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DNR.Core
{
    public static class StringsDecrypter
    {
        public static int DecryptedStrings { get; private set; }
        private static byte[] _encryptedData;

        public static void Execute(Context ctx)
        {
            var logger = ctx.Options.Logger;
            logger.Info("=== CONFUSEREX STRING CLEANER (DEBUG MODE) ===");
            
            // DEBUG: List ALL byte arrays in the module
            DebugFindAllByteArrays(ctx.Module, logger);
            
            // Try to find the encrypted data
            _encryptedData = FindEncryptedByteArray(ctx.Module, logger);
            
            if (_encryptedData == null)
            {
                logger.Error("CRITICAL: No encrypted data found!");
                logger.Info("Trying alternative search...");
                return;
            }
            
            logger.Success($"Found data array: {_encryptedData.Length} bytes");
            
            // Test decryption with known values from your output
            TestKnownValues(logger);
            
            // Find and process string decryption methods
            ProcessStringDecryption(ctx.Module, logger);
            
            logger.Success($"Decrypted {DecryptedStrings} strings!");
        }
        
        private static void DebugFindAllByteArrays(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("=== SEARCHING FOR ALL BYTE ARRAYS ===");
            int count = 0;
            
            foreach (var type in module.GetTypes())
            {
                foreach (var field in type.Fields)
                {
                    try
                    {
                        if (field.FieldType != null && 
                            field.FieldType.FullName.Contains("Byte[]"))
                        {
                            count++;
                            logger.Info($"#{count}: {type.Name}.{field.Name}");
                            logger.Info($"  Static: {field.IsStatic}, HasInit: {field.InitialValue != null}");
                            
                            if (field.InitialValue != null)
                            {
                                logger.Info($"  Size: {field.InitialValue.Length} bytes");
                                
                                // Show first few bytes
                                int show = Math.Min(16, field.InitialValue.Length);
                                var hex = new StringBuilder();
                                for (int i = 0; i < show; i++)
                                {
                                    hex.Append($"{field.InitialValue[i]:X2} ");
                                }
                                logger.Info($"  First {show} bytes: {hex}");
                                
                                // Count printable chars
                                int printables = 0;
                                for (int i = 0; i < Math.Min(100, field.InitialValue.Length); i++)
                                {
                                    byte b = field.InitialValue[i];
                                    if (b >= 32 && b <= 126 || b == 0) printables++;
                                }
                                logger.Info($"  Printable/null: {printables}/100");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.Error($"  Error: {ex.Message}");
                    }
                }
            }
            
            logger.Info($"Total byte arrays found: {count}");
        }
        
        private static byte[] FindEncryptedByteArray(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("=== LOOKING FOR ENCRYPTED STRING DATA ===");
            
            // First, look in <Module> class (most common)
            var moduleType = module.GlobalType;
            if (moduleType != null)
            {
                logger.Info($"Checking <Module> class...");
                foreach (var field in moduleType.Fields)
                {
                    if (field.IsStatic && field.InitialValue != null)
                    {
                        logger.Info($"  Field: {field.Name}, Size: {field.InitialValue.Length}");
                        if (field.InitialValue.Length > 1000)
                        {
                            logger.Success($"  FOUND LARGE ARRAY: {field.Name} ({field.InitialValue.Length} bytes)");
                            return field.InitialValue;
                        }
                    }
                }
            }
            
            // Look for any large static byte array
            foreach (var type in module.GetTypes())
            {
                foreach (var field in type.Fields)
                {
                    try
                    {
                        if (field.IsStatic && 
                            field.InitialValue != null && 
                            field.InitialValue.Length > 5000) // Very large = likely string data
                        {
                            logger.Success($"Found large array in {type.Name}.{field.Name}: {field.InitialValue.Length} bytes");
                            return field.InitialValue;
                        }
                    }
                    catch { }
                }
            }
            
            return null;
        }
        
        private static void TestKnownValues(Utils.ILogger logger)
        {
            logger.Info("=== TESTING WITH KNOWN VALUES ===");
            
            // Test with values from your earlier output
            int[] testValues = { -1277707744, 996003610, 441305532, 2086091522 };
            
            foreach (int val in testValues)
            {
                string result = TryDecryptValue(val);
                if (result != null)
                {
                    logger.Success($"Test {val} -> '{result}'");
                }
                else
                {
                    logger.Warning($"Test {val} -> FAILED");
                }
            }
        }
        
        private static string TryDecryptValue(int index)
        {
            if (_encryptedData == null) return null;
            
            // Convert negative index to positive
            if (index < 0)
            {
                index = _encryptedData.Length + index;
                if (index < 0 || index >= _encryptedData.Length) return null;
            }
            
            // Try different patterns
            return TryPattern1(index) ?? TryPattern2(index) ?? TryPattern3(index);
        }
        
        private static string TryPattern1(int index)
        {
            // Pattern: 4-byte length + UTF8
            if (index + 4 >= _encryptedData.Length) return null;
            
            int length = BitConverter.ToInt32(_encryptedData, index);
            if (length > 0 && length < 10000 && index + 4 + length <= _encryptedData.Length)
            {
                return Encoding.UTF8.GetString(_encryptedData, index + 4, length);
            }
            return null;
        }
        
        private static string TryPattern2(int index)
        {
            // Pattern: Null-terminated UTF8
            for (int i = index; i < _encryptedData.Length; i++)
            {
                if (_encryptedData[i] == 0)
                {
                    int length = i - index;
                    if (length > 0)
                    {
                        return Encoding.UTF8.GetString(_encryptedData, index, length);
                    }
                    return null;
                }
            }
            return null;
        }
        
        private static string TryPattern3(int index)
        {
            // Pattern: 2-byte length + Unicode
            if (index + 2 >= _encryptedData.Length) return null;
            
            int length = BitConverter.ToUInt16(_encryptedData, index);
            if (length > 0 && length < 10000 && index + 2 + length * 2 <= _encryptedData.Length)
            {
                return Encoding.Unicode.GetString(_encryptedData, index + 2, length * 2);
            }
            return null;
        }
        
        private static void ProcessStringDecryption(ModuleDefMD module, Utils.ILogger logger)
        {
            logger.Info("=== PROCESSING STRING DECRYPTION CALLS ===");
            
            int callCount = 0;
            
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    
                    callCount += ProcessMethod(method, logger);
                }
            }
            
            logger.Info($"Processed {callCount} method calls");
        }
        
        private static int ProcessMethod(MethodDef method, Utils.ILogger logger)
        {
            int processed = 0;
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Call && 
                    instructions[i].Operand is IMethod calledMethod)
                {
                    // Look for string decryption patterns
                    if (IsStringDecryptionMethod(calledMethod))
                    {
                        // Find the integer argument
                        int? index = FindIntegerArgument(instructions, i);
                        
                        if (index.HasValue)
                        {
                            string decrypted = TryDecryptValue(index.Value);
                            
                            if (!string.IsNullOrEmpty(decrypted))
                            {
                                // Replace the call
                                ReplaceWithString(instructions, i, index.Value, decrypted);
                                DecryptedStrings++;
                                processed++;
                                
                                if (decrypted.Length < 50)
                                {
                                    logger.Success($"[{index.Value}] '{decrypted}'");
                                }
                            }
                        }
                    }
                }
            }
            
            return processed;
        }
        
        private static bool IsStringDecryptionMethod(IMethod method)
        {
            // Methods that take int and return string
            return method.MethodSig != null &&
                   method.MethodSig.RetType != null &&
                   method.MethodSig.RetType.FullName == "System.String" &&
                   method.MethodSig.Params.Count == 1 &&
                   method.MethodSig.Params[0].FullName == "System.Int32";
        }
        
        private static int? FindIntegerArgument(IList<Instruction> instructions, int callIndex)
        {
            for (int i = callIndex - 1; i >= 0 && i >= callIndex - 10; i--)
            {
                if (instructions[i].IsLdcI4())
                {
                    return instructions[i].GetLdcI4Value();
                }
            }
            return null;
        }
        
        private static void ReplaceWithString(IList<Instruction> instructions, int callIndex, int originalIndex, string decrypted)
        {
            // Find and nop the ldc.i4
            for (int i = callIndex - 1; i >= 0 && i >= callIndex - 10; i--)
            {
                if (instructions[i].IsLdcI4() && instructions[i].GetLdcI4Value() == originalIndex)
                {
                    instructions[i].OpCode = OpCodes.Nop;
                    instructions[i].Operand = null;
                    break;
                }
            }
            
            // Replace call with string
            instructions[callIndex].OpCode = OpCodes.Ldstr;
            instructions[callIndex].Operand = decrypted;
        }
    }
}
