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

#pragma once

#include <Windows.h>

PCHAR getDLLDirFromFullPath(const char* file_path, LPVOID(pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD)) {
	int i = 0;
	while (file_path[i] != '\0') {
		i++;
	}
	i--;
	while (i >= 0 && (file_path[i] != '\\' && file_path[i] != '/')) {
		i--;
	}
	if (i < 0) {
		return NULL;
	}
	int dir_len = i + 1;
	PCHAR dir = (PCHAR)pVirtualAlloc(NULL, dir_len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	int j = 0;
	while (j < dir_len) {
		dir[j] = file_path[j];
		j++;
	}
	dir[dir_len] = '\0';
	return dir;
}

PCHAR getDLLNameFromFullPath(const char* full_path, LPVOID(pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD)) {
	int len = 0;
	const char* p = full_path;

	// Determine the length of the full path
	while (*p++) len++;

	// Find the last directory separator
	p = full_path + len - 1;
	while (p >= full_path && *p != '\\' && *p != '/') p--;

	// Allocate memory for the filename
	PCHAR filename = (PCHAR)pVirtualAlloc(NULL, len - (p - full_path) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy the filename into the allocated memory
	char* dst = filename;
	p++;
	while (*p) *dst++ = *p++;
	*dst = '\0';

	return filename;
}

int str_length(const char str[]) {
	int count;
	for (count = 0; str[count] != '\0'; ++count);
	return count;
}

PCHAR str_cat(const char* first, const char* sec, LPVOID(pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD)) {
	PCHAR addy = (PCHAR)pVirtualAlloc(NULL, str_length(first) + str_length(sec), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
	int count;
	for (count = 0; first[count] != '\0'; count++) {
		addy[count] = first[count];
	}
	int count2;
	for (count2 = 0; sec[count2] != '\0'; count2++) {
		addy[count + count2] = sec[count2];
	}
	count2++;
	addy[count + count2] = '\0';

	return addy;
}

void CopyFileFromTempToDir(const char* dirToCopyTo, const char* fileName, const char* backupName, LPVOID(pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD), DWORD(*pGetTempPathA)(DWORD, LPSTR), BOOL(*pCopyFileA)(LPCSTR, LPCSTR, BOOL))
{
	CHAR tempPath[MAX_PATH];
	DWORD pathLen = pGetTempPathA(MAX_PATH, tempPath);
	CHAR fullTempPath[MAX_PATH];
	for (int i = 0; i < pathLen; i++) {
		fullTempPath[i] = tempPath[i];
	}
	fullTempPath[pathLen] = '\0';

	PCHAR fileTempFilePath = str_cat(fullTempPath, backupName, pVirtualAlloc);
	PCHAR localDirFilePath = str_cat(dirToCopyTo, fileName, pVirtualAlloc);

	pCopyFileA(fileTempFilePath, localDirFilePath, TRUE);

	return;
}

void BackupFileToTemp(const char* dllPath, const char* backupName, LPVOID(pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD), DWORD(*pGetTempPathA)(DWORD, LPSTR), BOOL(*pCopyFileA)(LPCSTR, LPCSTR, BOOL))
{
	CHAR fullPath[MAX_PATH];
	DWORD pathLen = pGetTempPathA(MAX_PATH, fullPath);
	fullPath[pathLen] = '\0';

	PCHAR backupFullPath = str_cat(fullPath, backupName, pVirtualAlloc);
	pCopyFileA(dllPath, backupFullPath, FALSE);

	return;
}

DWORD64 FindSectionInAllModulesCurrentProc(char* sectionName, long* secSize, HMODULE(*pGetModuleHandleA)(LPCSTR)) {
	PPEB ppeb = (PPEB)__readgsqword(0x60);

	PLIST_ENTRY Head = &ppeb->Ldr->InMemoryOrderModuleList, Next;
	DWORD64 encScDynamicBase = 0;
	for (Next = Head->Flink; Next != Head; Next = Next->Flink) {
		PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)Next;
		auto name = Entry->FullDllName;
		char* buf = (PCHAR)name.Buffer;
		char bufa[200];
		int bufaLoc = 0;
		while (buf[0] != '\0' && buf[2] != '\0') {
			bufa[bufaLoc] = buf[0];
			bufaLoc++;
			buf += 2;
		}
		bufa[bufaLoc] = buf[0];
		bufa[bufaLoc + 1] = '\0';
		HANDLE modHandle = pGetModuleHandleA(bufa);

		PIMAGE_DOS_HEADER dosHeaderCurr = (PIMAGE_DOS_HEADER)modHandle;
		PIMAGE_NT_HEADERS imageNTHeadersCurr = (PIMAGE_NT_HEADERS)((DWORD64)modHandle + dosHeaderCurr->e_lfanew);
		DWORD64 sectionLocationCurr = (DWORD64)imageNTHeadersCurr + sizeof(DWORD64) + (sizeof(IMAGE_FILE_HEADER)) + (DWORD64)imageNTHeadersCurr->FileHeader.SizeOfOptionalHeader - 4;
		DWORD64 sectionSizeCurr = sizeof(IMAGE_SECTION_HEADER);

		for (int i = 0; i < imageNTHeadersCurr->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocationCurr;
			bool match = true;
			for (int x = 0; x < sizeof(sectionHeader->Name); x++) {
				if (sectionHeader->Name[x] == '\0') {
					break;
				}
				if (sectionHeader->Name[x] != sectionName[x]) {
					match = false;
					break;
				}
			}
			if (match) {
				encScDynamicBase = (DWORD64)modHandle + sectionHeader->VirtualAddress;
				*secSize = sectionHeader->SizeOfRawData;
				return encScDynamicBase;
			}

			sectionLocationCurr += sectionSizeCurr;
		}
	}
	return -1;
}
