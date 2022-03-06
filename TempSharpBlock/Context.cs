using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace TempSharpBlock
{/*
    public enum ContextFlags
    {
        All,
        Debug
    }

    public static class ContextFactory
    {
        public static Context Create(ContextFlags contextFlags)
        {
            if (IntPtr.Size == 8)
            {
                return new Context64(contextFlags);
            }
            else
            {
                return new Context32(contextFlags);
            }
        }
    }

    public abstract class Context : IDisposable
    {

        IntPtr mem;
        IntPtr memAligned;

        public Context()
        {
            //Get/SetThreadContext needs to be 16 byte aligned memory offset on x64
            mem = Marshal.AllocHGlobal(Marshal.SizeOf(ContextStruct) + 1024);
            memAligned = new IntPtr(mem.ToInt64() & ~0xF);
        }

        public void Dispose()
        {
            if (mem != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(mem);
            }
        }

        public bool GetContext(IntPtr thread)
        {
            Marshal.StructureToPtr(ContextStruct, memAligned, false);
            bool result = GetContext(thread, memAligned);
            ContextStruct = Marshal.PtrToStructure(memAligned, ContextStruct.GetType());
            return result;
        }

        public bool SetContext(IntPtr thread)
        {
            Marshal.StructureToPtr(ContextStruct, memAligned, false);
            return SetContext(thread, memAligned);
        }

        public ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }

        protected abstract object ContextStruct { get; set; }

        protected abstract bool SetContext(IntPtr thread, IntPtr context);

        protected abstract bool GetContext(IntPtr thread, IntPtr context);

        public abstract ulong Ip { get; set; }

        public abstract void SetResultRegister(ulong result);

        public abstract ulong GetCurrentReturnAddress(IntPtr hProcess);

        public abstract void PopStackPointer();

        public abstract void EnableBreakpoint(IntPtr address, int index);

        public abstract void ClearBreakpoint(int index);

        public abstract void EnableSingleStep();

        public abstract void SetRegister(int index, long value);

        public abstract long GetRegister(int index);

        public abstract long GetParameter(int index, IntPtr hProcess);
    }
    public class Context32 : Context
    {

        Structs.CONTEXT32 ctx = new Structs.CONTEXT32();

        public override ulong Ip
        {
            get => ctx.Eip; set => ctx.Eip = (uint)value;
        }

        protected override object ContextStruct { get => ctx; set => ctx = (Structs.CONTEXT32)value; }

        public Context32(ContextFlags contextFlags)
        {
            switch (contextFlags)
            {
                case ContextFlags.All:
                    ctx.ContextFlags = Structs.CONTEXT_FLAGS.CONTEXT_ALL;
                    break;
                case ContextFlags.Debug:
                    ctx.ContextFlags = Structs.CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS;
                    break;
            }
        }

        public override ulong GetCurrentReturnAddress(IntPtr hProcess)
        {
            byte[] returnAddress = new byte[4];
            IntPtr bytesRead;
            Structs.ReadProcessMemory(hProcess, new IntPtr((long)ctx.Esp), returnAddress, 4, out bytesRead);
            return BitConverter.ToUInt32(returnAddress, 0);
        }

        public override void SetResultRegister(ulong result)
        {
            ctx.Eax = (uint)result;
        }

        public override void PopStackPointer()
        {
            ctx.Esp += 4;
        }

        public override void EnableBreakpoint(IntPtr address, int index)
        {
            //Currently only supports first hardware breakpoint, could
            //be expanded to support up to 4 hardware breakpoint for altering
            //ETW and other potensial bypasses
            ctx.Dr0 = (uint)address.ToInt32();
            //Set bits 16-19 as 0, DR0 for execute HBP
            ctx.Dr7 = (uint)SetBits((ulong)ctx.Dr7, 16, 4, 0);
            //Set DR0 HBP as enabled
            ctx.Dr7 = (uint)SetBits((ulong)ctx.Dr7, 0, 2, 3);
            ctx.Dr6 = 0;
        }

        public override void EnableSingleStep()
        {
            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags |= (1 << 8);
        }

        public override void ClearBreakpoint(int index)
        {
            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags = 0;
        }

        protected override bool SetContext(IntPtr thread, IntPtr context)
        {
            return Structs.SetThreadContext(thread, context);
        }

        protected override bool GetContext(IntPtr thread, IntPtr context)
        {
            bool a = Structs.GetThreadContext(thread, ref context);
            Marshal.GetLastWin32Error();
            return a;
        }

        public override void SetRegister(int index, long value)
        {
            switch (index)
            {
                case 0:
                    ctx.Eax = (uint)value;
                    break;
                case 1:
                    ctx.Ebx = (uint)value;
                    break;
                case 2:
                    ctx.Ecx = (uint)value;
                    break;
                case 3:
                    ctx.Edx = (uint)value;
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        public override long GetRegister(int index)
        {
            switch (index)
            {
                case 0:
                    return (long)ctx.Eax;
                case 1:
                    return (long)ctx.Ebx;
                case 2:
                    return (long)ctx.Ecx;
                case 3:
                    return (long)ctx.Edx;
                default:
                    throw new NotImplementedException();
            }
        }

        public override long GetParameter(int index, IntPtr hProcess)
        {
            long parameterAddress = ctx.Esp + 4 + (index * 4);
            byte[] parameterValue = new byte[4];
            IntPtr bytesRead;
            Structs.ReadProcessMemory(hProcess, new IntPtr(parameterAddress), parameterValue, 4, out bytesRead);
            return BitConverter.ToUInt32(parameterValue, 0);
        }
    }
    public class Context64 : Context
    {

        Structs.CONTEXT64 ctx = new Structs.CONTEXT64();

        public override ulong Ip
        {
            get => ctx.Rip; set => ctx.Rip = value;
        }
        protected override object ContextStruct { get => ctx; set => ctx = (Structs.CONTEXT64)value; }

        public Context64(ContextFlags contextFlags)
        {
            switch (contextFlags)
            {
                case ContextFlags.All:
                    ctx.ContextFlags = Structs.CONTEXT64_FLAGS.CONTEXT64_ALL;
                    break;
                case ContextFlags.Debug:
                    ctx.ContextFlags = Structs.CONTEXT64_FLAGS.CONTEXT64_DEBUG_REGISTERS;
                    break;
            }
        }

        public override ulong GetCurrentReturnAddress(IntPtr hProcess)
        {
            byte[] returnAddress = new byte[8];
            IntPtr bytesRead;
            Structs.ReadProcessMemory(hProcess, new IntPtr((long)ctx.Rsp), returnAddress, 8, out bytesRead);
            return BitConverter.ToUInt64(returnAddress, 0);
        }

        public override void SetResultRegister(ulong result)
        {
            ctx.Rax = result;
        }

        public override void SetRegister(int index, long value)
        {
            switch (index)
            {
                case 0:
                    ctx.Rax = (ulong)value;
                    break;
                case 1:
                    ctx.Rbx = (ulong)value;
                    break;
                case 2:
                    ctx.Rcx = (ulong)value;
                    break;
                case 3:
                    ctx.Rdx = (ulong)value;
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        public override long GetRegister(int index)
        {
            switch (index)
            {
                case 0:
                    return (long)ctx.Rax;
                case 1:
                    return (long)ctx.Rbx;
                case 2:
                    return (long)ctx.Rcx;
                case 3:
                    return (long)ctx.Rdx;
                default:
                    throw new NotImplementedException();
            }
        }

        public override void PopStackPointer()
        {
            ctx.Rsp += 8;
        }

        public override void EnableBreakpoint(IntPtr address, int index)
        {

            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }

            //Set bits 16-31 as 0, which sets
            //DR0-DR3 HBP's for execute HBP
            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);

            //Set DRx HBP as enabled for local mode
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            ctx.Dr6 = 0;
        }

        public override void EnableSingleStep()
        {
            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags |= (1 << 8);
        }

        public override void ClearBreakpoint(int index)
        {

            //Clear the releveant hardware breakpoint
            switch (index)
            {
                case 0:
                    ctx.Dr0 = 0;
                    break;
                case 1:
                    ctx.Dr1 = 0;
                    break;
                case 2:
                    ctx.Dr2 = 0;
                    break;
                case 3:
                    ctx.Dr3 = 0;
                    break;
            }

            //Clear DRx HBP to disable for local mode
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 0);
            ctx.Dr6 = 0;
            ctx.EFlags = 0;
        }

        protected override bool SetContext(IntPtr thread, IntPtr context)
        {
            return Structs.SetThreadContext(thread, context);
        }

        protected override bool GetContext(IntPtr thread, IntPtr context)
        {
            return Structs.GetThreadContext(thread, ref context);
        }

        public override long GetParameter(int index, IntPtr hProcess)
        {

            switch (index)
            {
                case 0:
                    return (long)ctx.Rcx;
                case 1:
                    return (long)ctx.Rdx;
                case 2:
                    return (long)ctx.R8;
                case 3:
                    return (long)ctx.R9;
            }

            throw new NotImplementedException("Only 4 parameters or less currently supported");
        }
    }*/
}
