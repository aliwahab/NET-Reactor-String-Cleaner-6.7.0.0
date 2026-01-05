using System;
using System.Diagnostics;
using System.Reflection;
using HarmonyLib;

namespace DNR.Core
{
    // Modified for .NET 9 compatibility
    public static class StacktracePatcher
    {
        private const string HarmonyId = "DNR.stacktrace";
        private static Harmony _harmony;

        public static void Patch()
        {
            try
            {
                // .NET 9 doesn't have the same StackFrame.GetMethod() to patch
                // This patcher was mainly for .NET Framework obfuscated assemblies
                Console.WriteLine("[INFO] Stacktrace patching not required for .NET 9 targets");
                
                // Optional: Only patch if we detect .NET Framework assembly
                // _harmony = new Harmony(HarmonyId);
                // _harmony.PatchAll(Assembly.GetExecutingAssembly());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARNING] Stacktrace patching failed: {ex.Message}");
            }
        }

        public static void UnPatch()
        {
            _harmony?.UnpatchAll(HarmonyId);
            _harmony = null;
        }

        // Comment out or remove the HarmonyPatch attribute for .NET 9
        // [HarmonyPatch(typeof(StackFrame), "GetMethod")]
        public class PatchStackTraceGetMethod
        {
            public static MethodInfo MethodToReplace;

            public static void Postfix(ref MethodBase __result)
            {
                // This code path is for .NET Framework only
                // .NET Core/5/6/7/8/9 use different stack trace APIs
                Console.WriteLine("[DEBUG] Stack trace patching not supported in .NET 9");
            }
        }
    }
}
