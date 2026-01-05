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
        private static Dictionary<string, Func<int, string>> _decryptionMethods = new Dictionary<string, Func<int, string>>();

        public static void Execute(Context ctx)
        {
            var logger = ctx.Options.Logger;
            logger.Info("=== ADVANCED STRING DECRYPTION ===");
            
            // Find ALL encrypted data arrays
            FindAllEncryptedArrays(ctx.Module, logger);
            
            if (_encryptedData == null)
            {
                logger.Error("No encrypted data found!");
                return;
            }
            
            // Find ALL string decryption methods
            FindStringDecryptionMethods(ctx.Module, logger);
            
            logger.Success($"Found {_decryptionMethods.Count} decryption methods");
            logger.Success($"Data size: {_encryptedData.Length} bytes");
            
            // Process the entire module
            ProcessModule(ctx, logger);
            
            logger.Success($"Total strings decrypted: {DecryptedStrings}");
        }
        
        private static void FindAllEncryptedArrays(ModuleDefMD module, Utils.ILogger logger)
        {
            // Look for ALL static byte arrays
            foreach (var type in module.GetTypes())
            {
                foreach (var field in type.Fields)
                {
                    if (field.FieldType.FullName == "System.Byte[]" && 
                        field.IsStatic && 
                        field.InitialValue != null)
                    {
                        logger.Info($"Found array: {type.Name}.{field.Name} ({field.InitialValue.Length} bytes)");
                        
                        // Use the LARGEST array (likely contains strings)
                        if (_encryptedData == null || field.InitialValue.Length > _encryptedData.Length)
                        {
                            _encryptedData = field.InitialValue;
                        }
                    }
                }
            }
        }
        
        private static void FindStringDecryptionMethods(ModuleDefMD module, Utils.ILogger logger)
        {
            // Look for methods that take int and return string
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (method.MethodSig != null &&
                        method.MethodSig.RetType.FullName == "System.String" &&
                        method.MethodSig.Params.Count == 1 &&
                        method.MethodSig.Params[0].FullName == "System.Int32")
                    {
                        // This could be a string decryption method!
                        string key = $"{type.FullName}::{method.Name}";
                        
                        // Analyze the method to understand its algorithm
                        if (AnalyzeDecryptionMethod(method))
                        {
                            _decryptionMethods[key] = (index) => DecryptUsingMethod(index, method);
                            logger.Info($"Found decryption method: {method.Name}");
                        }
                    }
                }
            }
        }
        
        private static bool AnalyzeDecryptionMethod(MethodDef method)
        {
            if (!method.HasBody) return false;
            
            // Check for common patterns in the IL
            var instr = method.Body.Instructions;
            bool usesByteArray = false;
            bool usesEncoding = false;
            
            foreach (var il in instr)
            {
                if (il.OpCode == OpCodes.Ldsfld && il.Operand is IField field)
                {
                    if (field.FieldType.FullName == "System.Byte[]")
                        usesByteArray = true;
                }
                else if (il.OpCode == OpCodes.Call && il.Operand is IMethod called)
                {
                    if (called.FullName.Contains("Encoding::") || called.FullName.Contains("GetString"))
                        usesEncoding = true;
                }
            }
            
            return usesByteArray && usesEncoding;
        }
        
        private static string DecryptUsingMethod(int index, MethodDef method)
        {
            try
            {
                // Generic decryption based on common patterns
                if (index < 0)
                    index = _encryptedData.Length + index;
                
                if (index < 0 || index >= _encryptedData.Length)
                    return $"[ERROR: Index {index}]";
                
                // Try different patterns
                return TryPattern1(index) ?? TryPattern2(index) ?? $"[UNKNOWN: {index}]";
            }
            catch
            {
                return null;
            }
        }
        
        private static string TryPattern1(int index)
        {
            // Pattern 1: 4-byte length + UTF8 data
            if (index + 4 >= _encryptedData.Length) return null;
            
            int length = _encryptedData[index] | 
                        (_encryptedData[index + 1] << 8) | 
                        (_encryptedData[index + 2] << 16) | 
                        (_encryptedData[index + 3] << 24);
            
            if (length > 0 && index + 4 + length <= _encryptedData.Length)
            {
                return Encoding.UTF8.GetString(_encryptedData, index + 4, length).Replace("\0", "");
            }
            
            return null;
        }
        
        private static string TryPattern2(int index)
        {
            // Pattern 2: Null-terminated UTF8 string
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
        
        private static void ProcessModule(Context ctx, Utils.ILogger logger)
        {
            // Find ALL calls to string decryption methods and replace them
            foreach (var typeDef in ctx.Module.GetTypes())
            {
                if (!typeDef.HasMethods) continue;
                
                foreach (var methodDef in typeDef.Methods)
                {
                    if (!methodDef.HasBody) continue;
                    
                    ProcessMethod(methodDef, logger);
                }
            }
        }
        
        private static void ProcessMethod(MethodDef method, Utils.ILogger logger)
        {
            var instructions = method.Body.Instructions;
            
            for (int i = 0; i < instructions.Count; i++)
            {
                // Look for: call string METHOD(int32)
                if (instructions[i].OpCode == OpCodes.Call && 
                    instructions[i].Operand is IMethod calledMethod)
                {
                    // Check if this is a known decryption method
                    string methodKey = $"{calledMethod.DeclaringType.FullName}::{calledMethod.Name}";
                    
                    if (_decryptionMethods.ContainsKey(methodKey))
                    {
                        // Find the integer argument (should be ldc.i4 before call)
                        int argIndex = FindIntegerArgument(instructions, i);
                        if (argIndex >= 0)
                        {
                            int stringIndex = instructions[argIndex].GetLdcI4Value();
                            
                            try
                            {
                                string decrypted = _decryptionMethods[methodKey](stringIndex);
                                
                                if (!string.IsNullOrEmpty(decrypted))
                                {
                                    // Replace: ldc.i4 -> call
                                    // With:    nop    -> ldstr
                                    instructions[argIndex].OpCode = OpCodes.Nop;
                                    instructions[i].OpCode = OpCodes.Ldstr;
                                    instructions[i].Operand = decrypted;
                                    
                                    DecryptedStrings++;
                                    
                                    if (decrypted.Length > 1)
                                    {
                                        string preview = decrypted.Length > 30 ? 
                                            decrypted.Substring(0, 27) + "..." : decrypted;
                                        logger.Success($"Decrypted: '{preview}'");
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                logger.Error($"Failed to decrypt {stringIndex}: {ex.Message}");
                            }
                        }
                    }
                }
            }
        }
        
        private static int FindIntegerArgument(IList<Instruction> instructions, int callIndex)
        {
            // Look backward from the call for ldc.i4
            for (int i = callIndex - 1; i >= 0 && i >= callIndex - 5; i--)
            {
                if (instructions[i].IsLdcI4())
                    return i;
            }
            return -1;
        }
    }
}
