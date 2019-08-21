// PEDump.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>

#include <iostream>
#include <fstream>
#include <string>

#define DUMPFILE_EXTENSION ".exe$"

HANDLE ghFile = 0;
PVOID  gpBassAddr = 0;
PVOID  gpEndAddr = 0;

PVOID loadFile(std::string &filePath) {
	ghFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE pMap = CreateFileMapping(ghFile, NULL, PAGE_READONLY, 0, 0, NULL);

	gpBassAddr = MapViewOfFile(pMap, FILE_MAP_READ, 0, 0, 0);
	if (gpBassAddr == NULL) {
		std::cout << "[ERROR][MapViewOfFile]" << GetLastError() << std::endl;
		return 0;
	}
	std::ifstream ifile(filePath);
	ifile.seekg(0, std::ios_base::end);

	gpEndAddr = (PVOID)((ULONGLONG)gpBassAddr + ifile.tellg());

	return gpBassAddr;
}

ULONGLONG PossibleOnePEFind(ULONGLONG pBaseAddr, ULONGLONG pEndAddr) {
	/*
		可以多种实现，毕竟 MZ 头有可能被抹掉
	*/
	ULONGLONG pAddr = pBaseAddr;
	while (pAddr < pEndAddr) {
		if (*(INT*)pAddr == 'sihT') {
			if (*(INT*)(pAddr + 5) == 'gorp') {
				// todo  是否是已经加载的PE头，需要判断

				return pAddr - 0x4e;
			}
		}
		pAddr++;
	}

	return 0;
}

VOID Dump2File(ULONGLONG pStartAddr, ULONGLONG fileSize, std::string &filePath) {

	FILE* pFile;
	fopen_s(&pFile, filePath.c_str(), "wb");
	fwrite((const void *)pStartAddr, 1, fileSize, pFile);
	fclose(pFile);

}

INT DumpAllPe(PVOID pBaseAddr) {
	PVOID pStartAddr = pBaseAddr;
	INT iCount = 0;
	IMAGE_DOS_HEADER* pDosHeader = 0;
	BOOL bIs64;


	while (pStartAddr < gpEndAddr && (pDosHeader = (PIMAGE_DOS_HEADER)PossibleOnePEFind((ULONGLONG)pStartAddr, (ULONGLONG)gpEndAddr))) {
		iCount++;

		printf("[DEBUG] head offset %llx\r\n", (ULONGLONG)pDosHeader - (ULONGLONG)pStartAddr);

		IMAGE_FILE_HEADER* pFileHeader = 0;
		IMAGE_NT_HEADERS* pNtHeader = 0;
		ULONGLONG pFileStart = 0;
		ULONGLONG pFileSize = 0;
		std::string dumpFilePath;

		dumpFilePath.clear();
		dumpFilePath = std::to_string(iCount);
		
		dumpFilePath += DUMPFILE_EXTENSION;

		pNtHeader = (IMAGE_NT_HEADERS*)((LONGLONG)pDosHeader->e_lfanew + (LONGLONG)pDosHeader);

		switch (pNtHeader->FileHeader.SizeOfOptionalHeader) {
		case 0xe0:
			bIs64 = 0;
			break;
		case 0xf0:
			bIs64 = 1;
			break;
		default:
			return -1;
		}

		pFileStart = (ULONGLONG)pDosHeader;
		if (bIs64) {
			IMAGE_NT_HEADERS64* pNt = (IMAGE_NT_HEADERS64*)(pDosHeader->e_lfanew + (LONGLONG)pDosHeader);
			pFileSize = pNt->OptionalHeader.SizeOfImage;
		} else {
			IMAGE_NT_HEADERS32* pNt = (IMAGE_NT_HEADERS32*)(pDosHeader->e_lfanew + (LONGLONG)pDosHeader);
			pFileSize = pNt->OptionalHeader.SizeOfImage;
		}

		Dump2File(pFileStart, pFileSize, dumpFilePath);
		pStartAddr = (PVOID)(pFileStart + pFileSize);
	}

	return iCount;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("Need input file\r\n");
		return -1;
	}

	std::string filePath(argv[1]);
	PVOID pAddr = loadFile(filePath);

	DumpAllPe(pAddr);
}
