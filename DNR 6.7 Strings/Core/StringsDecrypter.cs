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
            logger.Info("=== CONFUSEREX STRING CLEANER ===");
            
            // STEP 1: Find the encrypted byte array
            _encryptedData = FindEncryptedByteArray(ctx.Module);
            if (_encryptedData == null)
            {
                logger.Error("Could not find encrypted data array!");
                return;
            }
            
            logger.Success($"Found data array: {_encryptedData.Length} bytes");
            
            // STEP 2: Find all string decryption methods
            var decryptionMethods = FindStringDecryptionMethods(ctx.Module, logger);
            
            // STEP 3: Process all methods in the module
            ProcessAllMethods(ctx.Module, decryptionMethods, logger);
            
            logger.Success($"Finished! Decrypted {DecryptedStrings} strings.");
        }
        
        private static byte[] FindEncryptedByteArray(ModuleDefMD module)
        {
            // Search all fields for static byte arrays
            foreach (var type in module.GetTypes())
            {
                foreach (var field in type.Fields)
                {
                    try
                    {
                        // Check if it's a static byte[] field
                        if (field.IsStatic && 
                            field.FieldType != null &&
                            field.FieldType.FullName == "System.Byte[]" &&
                            field.InitialValue != null &&
                            field.InitialValue.Length > 1000) // Likely string data
                        {
                            return field.InitialValue;
                        }
                    }
                    catch { }
                }
            }
            return null;
        }
        
        private static List<IMethod> FindStringDecryptionMethods(ModuleDefMD module, Utils.ILogger logger)
        {
            var methods = new List<IMethod>();
            
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    // Quick check: method takes int, returns string
                    if (method.MethodSig != null &&
                        method.MethodSig.RetType != null &&
                        method.MethodSig.RetType.FullName == "System.String" &&
                        method.MethodSig.Params.Count == 1 &&
                        method.MethodSig.Params[0].FullName == "System.Int32")
                    {
                        methods.Add(method);
                        logger.Info($"Found potential decryptor: {method.Name}");
                    }
                }
            }
            
            return methods;
        }
        
        private static void ProcessAllMethods(ModuleDefMD module, List<IMethod> decryptionMethods, Utils.ILogger logger)
        {
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    
                    ProcessMethodBody(method, decryptionMethods, logger);
                }
            }
        }
        
        private static void ProcessMethodBody(MethodDef method, List<IMethod> decryptionMethods, Utils.ILogger logger)
        {
            var instructions = method.Body.Instructions;
            bool modified = false;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Call && 
                    instructions[i].Operand is IMethod calledMethod)
                {
                    // Check if this is a string decryption method
                    if (decryptionMethods.Contains(calledMethod))
                    {
                        // Find the integer argument (should be before the call)
                        int? stringIndex = FindIntegerArgument(instructions, i);
                        
                        if (stringIndex.HasValue)
                        {
                            string decrypted = DecryptString(stringIndex.Value);
                            
                            if (!string.IsNullOrEmpty(decrypted))
                            {
                                // Replace the call with the decrypted string
                                ReplaceCallWithString(instructions, i, stringIndex.Value, decrypted);
                                DecryptedStrings++;
                                modified = true;
                                
                                // Log only meaningful strings
                                if (decrypted.Length > 1 && decrypted.Length < 100)
                                {
                                    logger.Success($"'{decrypted}'");
                                }
                            }
                        }
                    }
                }
            }
            
            if (modified)
            {
                method.Body.OptimizeMacros();
                method.Body.SimplifyBranches();
            }
        }
        
        private static int? FindIntegerArgument(IList<Instruction> instructions, int callIndex)
        {
            // Look backwards for ldc.i4 (up to 5 instructions back)
            for (int j = callIndex - 1; j >= 0 && j >= callIndex - 5; j--)
            {
                if (instructions[j].IsLdcI4())
                {
                    return instructions[j].GetLdcI4Value();
                }
            }
            return null;
        }
        
        private static string DecryptString(int index)
        {
            if (_encryptedData == null) return null;
            
            // Handle negative indices (common in obfuscation)
            if (index < 0)
            {
                index = _encryptedData.Length + index;
                if (index < 0) return null;
            }
            
            // Check bounds
            if (index >= _encryptedData.Length) return null;
            
            try
            {
                // Try Pattern 1: 4-byte length + UTF8 data
                if (index + 4 < _encryptedData.Length)
                {
                    int length = _encryptedData[index] | 
                                (_encryptedData[index + 1] << 8) | 
                                (_encryptedData[index + 2] << 16) | 
                                (_encryptedData[index + 3] << 24);
                    
                    if (length > 0 && length < 10000 && index + 4 + length <= _encryptedData.Length)
                    {
                        string result = Encoding.UTF8.GetString(_encryptedData, index + 4, length);
                        return CleanString(result);
                    }
                }
                
                // Try Pattern 2: Null-terminated string
                for (int i = index; i < _encryptedData.Length; i++)
                {
                    if (_encryptedData[i] == 0)
                    {
                        int length = i - index;
                        if (length > 0 && length < 10000)
                        {
                            string result = Encoding.UTF8.GetString(_encryptedData, index, length);
                            return CleanString(result);
                        }
                        break;
                    }
                }
                
                // Try Pattern 3: Raw bytes as ASCII
                if (index < _encryptedData.Length)
                {
                    int maxLength = Math.Min(100, _encryptedData.Length - index);
                    string result = Encoding.ASCII.GetString(_encryptedData, index, maxLength);
                    result = result.Split('\0')[0]; // Take until first null
                    if (result.Length > 0) return CleanString(result);
                }
            }
            catch { }
            
            return null;
        }
        
        private static string CleanString(string str)
        {
            if (string.IsNullOrEmpty(str)) return str;
            
            // Remove control characters except basic whitespace
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
        
        private static void ReplaceCallWithString(IList<Instruction> instructions, int callIndex, int originalIndex, string decrypted)
        {
            // Find the ldc.i4 instruction (the string index)
            int ldcIndex = -1;
            for (int j = callIndex - 1; j >= 0 && j >= callIndex - 5; j--)
            {
                if (instructions[j].IsLdcI4() && instructions[j].GetLdcI4Value() == originalIndex)
                {
                    ldcIndex = j;
                    break;
                }
            }
            
            if (ldcIndex != -1)
            {
                // Replace: ldc.i4 INDEX -> call DECRYPTOR
                // With:    nop           -> ldstr "DECRYPTED"
                instructions[ldcIndex].OpCode = OpCodes.Nop;
                instructions[ldcIndex].Operand = null;
                instructions[callIndex].OpCode = OpCodes.Ldstr;
                instructions[callIndex].Operand = decrypted;
            }
            else
            {
                // Just replace the call with ldstr
                instructions[callIndex].OpCode = OpCodes.Ldstr;
                instructions[callIndex].Operand = decrypted;
            }
        }
    }
}
