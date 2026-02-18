using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace NRE.Builder.Utilities
{
    /// <summary>
    /// Obfuscation: rename types, methods, fields, parameters, namespaces to confusing names;
    /// control flow obfuscation applied per-method. Preserves entry point so the assembly still runs.
    /// </summary>
    public static class AssemblyObfuscator
    {
        private static readonly Random Rng = new Random();
        // Lookalike chars to make names hard to read in dnSpy (l I 1 O 0 o S 5 etc.)
        private static readonly char[] ConfusingChars = { 'l', 'I', '1', 'O', '0', 'o', 'S', '5', 's', 'Z', 'z', '2', 'Q', 'G', '6', 'b', 'B', '8', 'g', 'q', 'L', 'i', 'T', '7', 'J', 'j', 'Y', 'y', 'U', 'u', 'V', 'v', 'W', 'w', 'N', 'n', 'M', 'm', 'H', 'h', 'K', 'k', 'P', 'p', 'R', 'r', 'D', 'd', 'E', 'e', 'A', 'a', 'F', 'f', 'X', 'x', 'C', 'c', 't', '3', '4', '9' };

        public static bool ObfuscateStubOutput(string buildOutDir, out string obfuscatedDir)
        {
            obfuscatedDir = null;
            string stubExe = Path.Combine(buildOutDir, "NRE.Stub.exe");
            if (!File.Exists(stubExe))
                return false;

            obfuscatedDir = buildOutDir + "_obf";
            try
            {
                if (Directory.Exists(obfuscatedDir))
                    Directory.Delete(obfuscatedDir, true);
                Directory.CreateDirectory(obfuscatedDir);
            }
            catch
            {
                return false;
            }

            try
            {
                var resolver = new DefaultAssemblyResolver();
                resolver.AddSearchDirectory(buildOutDir);
                var readerParams = new ReaderParameters
                {
                    AssemblyResolver = resolver,
                    InMemory = true,
                    ReadWrite = false
                };

                using (var asmDef = AssemblyDefinition.ReadAssembly(stubExe, readerParams))
                {
                    var entryPoint = asmDef.MainModule.EntryPoint;
                    var names = new HashSet<string>(StringComparer.Ordinal);
                    string obfNs = ConfusingName(8, 14, names);

                    foreach (var type in GetAllTypes(asmDef.MainModule))
                    {
                        if (type.Name == "<Module>" || type.Namespace == "<Module>")
                            continue;
                        type.Namespace = obfNs;
                        type.Name = ConfusingName(10, 18, names);
                        foreach (var method in type.Methods)
                        {
                            if (method == entryPoint)
                                continue;
                            if (method.Name == ".ctor" || method.Name == ".cctor")
                                continue;
                            method.Name = ConfusingName(8, 16, names);
                            foreach (var p in method.Parameters)
                            {
                                if (string.IsNullOrEmpty(p.Name)) continue;
                                p.Name = ConfusingName(6, 12, names);
                            }
                        }
                        foreach (var field in type.Fields)
                        {
                            if (field.Name == "value__" && type.IsEnum) continue;
                            field.Name = ConfusingName(8, 14, names);
                        }
                        foreach (var prop in type.Properties)
                        {
                            if (prop.Name != "value__")
                                prop.Name = ConfusingName(8, 14, names);
                        }
                        foreach (var ev in type.Events)
                            ev.Name = ConfusingName(8, 14, names);
                    }

                    foreach (var type in GetAllTypes(asmDef.MainModule))
                    {
                        if (type.Name == "<Module>" || type.Namespace == "<Module>") continue;
                        foreach (var method in type.Methods)
                        {
                            if (method == entryPoint || method.Name == ".ctor" || method.Name == ".cctor")
                                continue;
                            ControlFlowObfuscation.ApplyToMethod(method, asmDef.MainModule);
                        }
                    }

                    var writePath = Path.Combine(obfuscatedDir, Path.GetFileName(stubExe));
                    var writerParams = new WriterParameters { WriteSymbols = false };
                    asmDef.Write(writePath, writerParams);
                }

                foreach (var file in Directory.GetFiles(buildOutDir))
                {
                    var name = Path.GetFileName(file);
                    if (name == null)
                        continue;
                    if (string.Equals(name, "NRE.Stub.exe", StringComparison.OrdinalIgnoreCase))
                        continue;
                    var dest = Path.Combine(obfuscatedDir, name);
                    try
                    {
                        File.Copy(file, dest, true);
                    }
                    catch { }
                }

                return File.Exists(Path.Combine(obfuscatedDir, "NRE.Stub.exe"));
            }
            catch
            {
                try { if (Directory.Exists(obfuscatedDir)) Directory.Delete(obfuscatedDir, true); } catch { }
                obfuscatedDir = null;
                return false;
            }
        }

        private static IEnumerable<TypeDefinition> GetAllTypes(ModuleDefinition module)
        {
            foreach (var type in module.Types)
            {
                yield return type;
                foreach (var nested in GetNestedTypes(type))
                    yield return nested;
            }
        }

        private static IEnumerable<TypeDefinition> GetNestedTypes(TypeDefinition type)
        {
            foreach (var nested in type.NestedTypes)
            {
                yield return nested;
                foreach (var n2 in GetNestedTypes(nested))
                    yield return n2;
            }
        }

        private static string ConfusingName(int minLen, int maxLen, HashSet<string> used)
        {
            string name;
            do
            {
                int len = Rng.Next(minLen, maxLen + 1);
                var sb = new StringBuilder(len);
                for (int i = 0; i < len; i++)
                    sb.Append(ConfusingChars[Rng.Next(ConfusingChars.Length)]);
                name = sb.ToString();
            } while (used.Contains(name) || string.IsNullOrEmpty(name));
            used.Add(name);
            return name;
        }
    }
}
