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
            logger.Info("Starting ConfuserEx 1.6 string decryption...");

            foreach (var typeDef in ctx.Module.GetTypes().Where(x => x.HasMethods))
            foreach (var methodDef in typeDef.Methods.Where(x => x.HasBody)) 
            {
                var instr = methodDef.Body.Instructions;
                
                for (var i = 0; i < instr.Count; i++)
                {
                    // Pattern: ldc.i4 -> call ???????????????? (string decrypter)
                    if (instr[i].OpCode == OpCodes.Call && 
                        instr[i].Operand is IMethod decMethod &&
                        i > 0 && instr[i - 1].IsLdcI4())
                    {
                        try 
                        {
                            var encryptedValue = instr[i - 1].GetLdcI4Value();
                            
                            // Get method name for logging
                            var methodName = decMethod.Name;
                            if (methodName.Contains("?"))
                                methodName = "ObfuscatedDecryptor";
                            
                            // Try to decrypt
                            string decrypted = DecryptConfuserEx16(encryptedValue, decMethod, ctx.Module);
                            
                            if (decrypted != null)
                            {
                                // Replace the call with the decrypted string
                                instr[i - 1].OpCode = OpCodes.Nop;
                                instr[i].OpCode = OpCodes.Ldstr;
                                instr[i].Operand = decrypted;
                                
                                DecryptedStrings++;
                                logger.Success($"Decrypted: '{decrypted}' (from: {encryptedValue})");
                            }
                            else
                            {
                                logger.Warning($"Found encrypted value: {encryptedValue} in {methodName}");
                            }
                        }
                        catch (Exception e) 
                        {
                            logger.Error($"Error: {e.Message}");
                        }
                    }
                }
            }
            
            logger.Success($"Decrypted {DecryptedStrings} strings!");
        }
        
        private static string DecryptConfuserEx16(int encrypted, IMethod decMethod, ModuleDefMD module)
        {
            // Try common XOR keys
            int[] commonKeys = { 0x2A, 0x7F, 0xFF, 0x100, 0x2D, 0x5A, 0xA5, 0x1337, 0xCAFE };
            
            foreach (var key in commonKeys)
            {
                int result = encrypted ^ key;
                
                // Try as single character
                if (result > 0x20 && result < 0x7F)
                {
                    return new string((char)result, 1);
                }
                
                // Try as UTF-16 string
                byte[] bytes = BitConverter.GetBytes(result);
                string asString = Encoding.Unicode.GetString(bytes);
                asString = asString.Trim('\0');
                if (IsPrintable(asString) && asString.Length > 0)
                {
                    return asString;
                }
            }
            
            // Analyze the actual decryption method
            var methodDef = decMethod.ResolveMethodDef();
            if (methodDef != null && methodDef.HasBody)
            {
                return AnalyzeDecryptionMethod(encrypted, methodDef);
            }
            
            return null;
        }
        
        private static string AnalyzeDecryptionMethod(int encrypted, MethodDef methodDef)
        {
            var instr = methodDef.Body.Instructions;
            int? key = null;
            OpCode? operation = null;
            
            for (int i = 0; i < instr.Count; i++)
            {
                if (instr[i].IsLdcI4())
                {
                    int value = instr[i].GetLdcI4Value();
                    
                    // Skip the encrypted value parameter
                    if (i == 0 && value == encrypted) continue;
                    
                    key = value;
                }
                else if (instr[i].OpCode.Code == Code.Xor)
                {
                    operation = instr[i].OpCode;
                }
                else if (instr[i].OpCode.Code == Code.Add)
                {
                    operation = instr[i].OpCode;
                }
                else if (instr[i].OpCode.Code == Code.Sub)
                {
                    operation = instr[i].OpCode;
                }
            }
            
            if (key.HasValue && operation.HasValue)
            {
                int result = 0;
                
                if (operation.Value.Code == Code.Xor)
                    result = encrypted ^ key.Value;
                else if (operation.Value.Code == Code.Add)
                    result = encrypted + key.Value;
                else if (operation.Value.Code == Code.Sub)
                    result = encrypted - key.Value;
                
                // Convert to string
                try
                {
                    byte[] bytes = BitConverter.GetBytes(result);
                    string str = Encoding.Unicode.GetString(bytes).Trim('\0');
                    if (IsPrintable(str)) return str;
                }
                catch { }
            }
            
            return null;
        }
        
        private static bool IsPrintable(string str)
        {
            if (string.IsNullOrEmpty(str)) return false;
            
            foreach (char c in str)
            {
                if (c == '\0') continue;
                if (char.IsControl(c) && c != '\n' && c != '\r' && c != '\t')
                    return false;
            }
            return true;
        }
    }
}
