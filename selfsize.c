#include <stdio.h>
#include <inttypes.h>
#include <Windows.h>

int main(int argc, char *argv[]) {
    LARGE_INTEGER liFileSize = { 0 };
    DWORD dwPESize = 0;
    DWORD dwRead, dwMaxPointer = 0;
    WORD i;
    BYTE pBuff[4096] = { 0 };
    IMAGE_DOS_HEADER *pDOSHeader;
    IMAGE_NT_HEADERS *pHeader;
    IMAGE_SECTION_HEADER *pSectionTable;

    /* Open exe file */
    GetModuleFileNameA(NULL, (CHAR *)pBuff, sizeof(pBuff));
    HANDLE hFile = CreateFileA((CHAR *)pBuff, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (INVALID_HANDLE_VALUE == hFile)
        return -1;

    if (!ReadFile(hFile, pBuff, sizeof(pBuff), &dwRead, NULL)) {
        CloseHandle(hFile);
        return -1;
    }

    GetFileSizeEx(hFile, &liFileSize);
    CloseHandle(hFile);

    pDOSHeader = (IMAGE_DOS_HEADER *)pBuff;

    if (IMAGE_DOS_SIGNATURE != pDOSHeader->e_magic)
        return -1;

    if ((ULONG)(pDOSHeader->e_lfanew) >= (ULONG)(sizeof(pBuff) - sizeof(IMAGE_NT_HEADERS)))
        return -1;

    /* Locate PE header */
    pHeader = (IMAGE_NT_HEADERS *)(pBuff + pDOSHeader->e_lfanew);

    if (IMAGE_NT_SIGNATURE != pHeader->Signature)
        return -1;

    pSectionTable = (IMAGE_SECTION_HEADER *)((BYTE *)pHeader + sizeof(IMAGE_NT_HEADERS));

    if ((BYTE *)pSectionTable >= (pBuff + sizeof(pBuff)))
        return -1;

    /* For each section */
    for (i = 0; i < pHeader->FileHeader.NumberOfSections; ++i, pSectionTable++) {
        if (pSectionTable->PointerToRawData > dwMaxPointer) {
            dwMaxPointer = pSectionTable->PointerToRawData;
            dwPESize = pSectionTable->PointerToRawData + pSectionTable->SizeOfRawData;
        }
    }

    /* @copy /b src.exe+your.data dst.exe */
    printf("FileSize: %" PRId64 " bytes\n", liFileSize.QuadPart);
    printf("PESize: %u bytes\n", dwPESize);

    return 0;
}
