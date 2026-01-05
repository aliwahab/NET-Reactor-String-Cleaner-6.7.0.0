using System;
using System.Linq;
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
            logger.Info("Starting string decryption...");

            foreach (var typeDef in ctx.Module.GetTypes().Where(x => x.HasMethods))
            foreach (var methodDef in typeDef.Methods.Where(x => x.HasBody)) 
            {
                var instr = methodDef.Body.Instructions;
                
                for (var i = 0; i < instr.Count; i++)
                {
                    if (instr[i].OpCode == OpCodes.Call && 
                        instr[i].Operand is IMethod decMethod &&
                        i > 0 && instr[i - 1].IsLdcI4())
                    {
                        try 
                        {
                            var encryptedValue = instr[i - 1].GetLdcI4Value();
                            
                            // SIMPLE XOR TEST - Most common
                            int[] testKeys = { 0x2A, 0x7F, 0xFF, 0x2D, 0x5A, 0xA5 };
                            
                            foreach (var key in testKeys)
                            {
                                int test = encryptedValue ^ key;
                                
                                // If result looks like small string
                                if (test > 32 && test < 126)
                                {
                                    string decrypted = new string((char)test, 1);
                                    
                                    instr[i - 1].OpCode = OpCodes.Nop;
                                    instr[i].OpCode = OpCodes.Ldstr;
                                    instr[i].Operand = decrypted;
                                    
                                    DecryptedStrings++;
                                    logger.Success($"XOR {key:X}: '{decrypted}' from {encryptedValue}");
                                    break;
                                }
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
    }
}
