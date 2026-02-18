using System;
using System.Collections.Generic;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace NRE.Builder.Utilities
{
    /// <summary>
    /// Control flow obfuscation: flattening, opaque predicates, junk code.
    /// </summary>
    internal static class ControlFlowObfuscation
    {
        private static readonly Random Rng = new Random();

        public static void ApplyToMethod(MethodDefinition method, ModuleDefinition module)
        {
            if (method?.Body == null || method.Body.Instructions == null || method.Body.Instructions.Count < 3)
                return;
            // Skip only methods with try/filter/finally (complex exception handling)
            if (method.Body.ExceptionHandlers.Count > 2)
                return;

            try
            {
                method.Body.SimplifyMacros();
                InsertJunkCode(method);
                InsertOpaquePredicates(method);
                InsertJunkCode(method);
                if (method.Body.Instructions.Count >= 6 && method.Body.Instructions.Count <= 350 && CanFlatten(method))
                    FlattenControlFlow(method, module);
                InsertOpaquePredicates(method);
                method.Body.OptimizeMacros();
            }
            catch { }
        }

        private static void InsertJunkCode(MethodDefinition method)
        {
            var body = method.Body;
            var ins = body.Instructions;
            if (ins.Count < 3)
                return;

            var junkLocal = new VariableDefinition(method.Module.ImportReference(typeof(int)));
            body.Variables.Add(junkLocal);
            var il = body.GetILProcessor();

            int insertAt = method.IsStatic ? 0 : 1;
            if (insertAt < ins.Count)
            {
                var first = ins[insertAt];
                il.InsertBefore(first, il.Create(OpCodes.Ldc_I4, Rng.Next(0, 0x10000)));
                il.InsertBefore(first, il.Create(OpCodes.Stloc, junkLocal));
            }

            int junkCount = Math.Min(14, Math.Max(4, ins.Count / 3));
            for (int i = 0; i < junkCount; i++)
            {
                int idx = Rng.Next(ins.Count / 2, Math.Max(ins.Count / 2 + 1, ins.Count - 1));
                var target = ins[idx];
                if (target.OpCode == OpCodes.Ret || target.OpCode == OpCodes.Throw)
                    continue;
                if (Rng.Next(2) == 0)
                {
                    il.InsertBefore(target, il.Create(OpCodes.Ldloc, junkLocal));
                    il.InsertBefore(target, il.Create(OpCodes.Pop));
                }
                else
                {
                    il.InsertBefore(target, il.Create(OpCodes.Ldc_I4, Rng.Next(0, 256)));
                    il.InsertBefore(target, il.Create(OpCodes.Ldc_I4, 0));
                    il.InsertBefore(target, il.Create(OpCodes.Add));
                    il.InsertBefore(target, il.Create(OpCodes.Pop));
                }
            }
        }

        private static void InsertOpaquePredicates(MethodDefinition method)
        {
            var body = method.Body;
            var ins = body.Instructions;
            if (ins.Count < 5)
                return;

            var il = body.GetILProcessor();
            int count = Math.Min(10, Math.Max(3, ins.Count / 4));
            for (int i = 0; i < count; i++)
            {
                int idx = Rng.Next(2, ins.Count - 2);
                var target = ins[idx];
                if (target.OpCode == OpCodes.Ret || target.OpCode == OpCodes.Throw || target.OpCode == OpCodes.Switch)
                    continue;
                il.InsertBefore(target, il.Create(OpCodes.Ldc_I4_1));
                il.InsertBefore(target, il.Create(OpCodes.Brtrue, target));
            }
        }

        private static void FlattenControlFlow(MethodDefinition method, ModuleDefinition module)
        {
            var body = method.Body;
            var ins = body.Instructions;
            if (ins.Count < 8)
                return;

            var blocks = BuildBasicBlocks(method);
            if (blocks == null || blocks.Count < 2 || blocks.Count > 80)
                return;

            var stateVar = new VariableDefinition(module.ImportReference(typeof(int)));
            body.Variables.Add(stateVar);
            var il = body.GetILProcessor();
            body.Instructions.Clear();

            var dispatcher = il.Create(OpCodes.Nop);
            var exitBlock = il.Create(OpCodes.Nop);

            var blockLabels = new List<Instruction>(blocks.Count);
            for (int i = 0; i < blocks.Count; i++)
                blockLabels.Add(il.Create(OpCodes.Nop));

            il.Append(il.Create(OpCodes.Ldc_I4_0));
            il.Append(il.Create(OpCodes.Stloc, stateVar));
            il.Append(il.Create(OpCodes.Br, dispatcher));

            il.Append(dispatcher);
            il.Append(il.Create(OpCodes.Ldloc, stateVar));
            il.Append(il.Create(OpCodes.Switch, blockLabels.ToArray()));
            il.Append(il.Create(OpCodes.Br, exitBlock));

            for (int b = 0; b < blocks.Count; b++)
            {
                var block = blocks[b];
                il.Append(blockLabels[b]);
                foreach (var instr in block)
                {
                    if (instr.OpCode == OpCodes.Ret)
                    {
                        il.Append(il.Create(OpCodes.Br, exitBlock));
                        continue;
                    }
                    if (instr.OpCode == OpCodes.Br || instr.OpCode == OpCodes.Br_S)
                    {
                        int targetBlock = GetBlockIndex(blocks, instr.Operand as Instruction);
                        if (targetBlock >= 0)
                        {
                            il.Append(il.Create(OpCodes.Ldc_I4, targetBlock));
                            il.Append(il.Create(OpCodes.Stloc, stateVar));
                            il.Append(il.Create(OpCodes.Br, dispatcher));
                        }
                        continue;
                    }
                    if (instr.OpCode == OpCodes.Brtrue || instr.OpCode == OpCodes.Brtrue_S ||
                        instr.OpCode == OpCodes.Brfalse || instr.OpCode == OpCodes.Brfalse_S)
                    {
                        int trueBlock = GetBlockIndex(blocks, instr.Operand as Instruction);
                        int falseBlock = b + 1 < blocks.Count ? b + 1 : b;
                        if (trueBlock >= 0)
                        {
                            var trueLabel = il.Create(OpCodes.Nop);
                            il.Append(il.Create(instr.OpCode == OpCodes.Brtrue || instr.OpCode == OpCodes.Brtrue_S ? OpCodes.Brtrue : OpCodes.Brfalse, trueLabel));
                            il.Append(il.Create(OpCodes.Ldc_I4, falseBlock));
                            il.Append(il.Create(OpCodes.Stloc, stateVar));
                            il.Append(il.Create(OpCodes.Br, dispatcher));
                            il.Append(trueLabel);
                            il.Append(il.Create(OpCodes.Ldc_I4, trueBlock));
                            il.Append(il.Create(OpCodes.Stloc, stateVar));
                            il.Append(il.Create(OpCodes.Br, dispatcher));
                        }
                        continue;
                    }
                    il.Append(instr);
                }
                if (b + 1 < blocks.Count)
                {
                    il.Append(il.Create(OpCodes.Ldc_I4, b + 1));
                    il.Append(il.Create(OpCodes.Stloc, stateVar));
                    il.Append(il.Create(OpCodes.Br, dispatcher));
                }
            }

            il.Append(exitBlock);
            il.Append(il.Create(OpCodes.Ret));
        }

        private static bool CanFlatten(MethodDefinition method)
        {
            // Allow Brtrue/Brfalse (we handle them in FlattenControlFlow). Only skip Switch (not implemented in dispatcher).
            foreach (var i in method.Body.Instructions)
                if (i.OpCode == OpCodes.Switch)
                    return false;
            return true;
        }

        private static List<List<Instruction>> BuildBasicBlocks(MethodDefinition method)
        {
            var body = method.Body;
            var ins = body.Instructions;
            var branchTargets = new HashSet<Instruction>();
            foreach (var i in ins)
            {
                if (i.Operand is Instruction target)
                    branchTargets.Add(target);
                if (i.OpCode == OpCodes.Switch && i.Operand is Instruction[] targets)
                    foreach (var t in targets) branchTargets.Add(t);
            }

            var blocks = new List<List<Instruction>>();
            List<Instruction> current = null;
            for (int i = 0; i < ins.Count; i++)
            {
                var instr = ins[i];
                if (branchTargets.Contains(instr) && current != null && current.Count > 0)
                {
                    blocks.Add(current);
                    current = new List<Instruction>();
                }
                if (current == null)
                    current = new List<Instruction>();
                current.Add(instr);
                var op = instr.OpCode;
                if (op == OpCodes.Ret || op == OpCodes.Throw || op == OpCodes.Br || op == OpCodes.Br_S ||
                    op == OpCodes.Brtrue || op == OpCodes.Brtrue_S || op == OpCodes.Brfalse || op == OpCodes.Brfalse_S ||
                    op == OpCodes.Switch || op == OpCodes.Jmp)
                {
                    blocks.Add(current);
                    current = new List<Instruction>();
                }
            }
            if (current != null && current.Count > 0)
                blocks.Add(current);
            return blocks;
        }

        private static int GetBlockIndex(List<List<Instruction>> blocks, Instruction target)
        {
            if (target == null) return -1;
            for (int i = 0; i < blocks.Count; i++)
                if (blocks[i].Count > 0 && blocks[i][0] == target)
                    return i;
            return -1;
        }
    }
}
