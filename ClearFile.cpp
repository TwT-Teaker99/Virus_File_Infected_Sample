#include <stdio.h>
#include <windows.h>
using namespace std;

DWORD Align(DWORD size, DWORD align);
bool DelSection(char* filepath);

char filepath[] = "D:\\gen1.exe";    //file path to be infected 
BYTE secName[8] = ".viral";         //Name of section infected

int main(int argc, char* argv[])
{
    DelSection(filepath);

    return 0;
}

//Function: rounding size according to alignment
DWORD Align(DWORD size, DWORD align)
{
    if (!(size % align))
        return size;
    else
        return (size / align + 1) * align;
}
//Function: add blank section to PE file
bool DelSection(char* filepath)
{
    HANDLE file = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL, "Error opening file", NULL, MB_OK);
        return false;
    }

    DWORD fileSize = GetFileSize(file, NULL);
    BYTE* pByte = new BYTE[fileSize];
    DWORD dw;
    ReadFile(file, pByte, fileSize, &dw, NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pByte;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        MessageBoxA(NULL, "Not PE file", NULL, MB_OK);
        return false;
    }

    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(pByte + dosHeader->e_lfanew + sizeof(DWORD));
    PIMAGE_OPTIONAL_HEADER OptionHeader = (PIMAGE_OPTIONAL_HEADER)(pByte + dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    //check file 32bit
    if (OptionHeader->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        MessageBoxA(NULL, "Not PE file 32bit!", NULL, MB_OK);
        return FALSE;
    }
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(pByte + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    WORD last = fileHeader->NumberOfSections - 1;
    fileSize -= sectionHeader[last].SizeOfRawData;
    //check name of last section
    for (int i = 0; i < 8; i++)
    {
        if (sectionHeader[last].Name[i] != secName[i]) {
            MessageBoxA(NULL, "Not file injected!", NULL, MB_OK);
            return false;
        }
    }
    //read OEP save in shellcode
    //0xA89 offset save OEP
    SetFilePointer(file, sectionHeader[last].PointerToRawData + 0xA89, NULL, FILE_BEGIN);
    BYTE* pTemp = new BYTE;
    ReadFile(file, pTemp, 4, &dw, 0); 

    SetFilePointer(file, fileSize, NULL, FILE_BEGIN);
    //truncate file size
    if (SetEndOfFile(file) == 0) {
        MessageBoxA(NULL, "False!", NULL, MB_OK);
        return FALSE;
    }
    //fix SizeOfImage, NumOfSec
    OptionHeader->SizeOfImage -= Align(sectionHeader[last].Misc.VirtualSize, OptionHeader->SectionAlignment);
    fileHeader->NumberOfSections -= 1;
    //clear sectionHeader
    memset(&sectionHeader[last], 0, sizeof(IMAGE_SECTION_HEADER));
    //write file
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    WriteFile(file, pByte, fileSize, &dw, NULL);
    //write override OEP 
    SetFilePointer(file, dosHeader->e_lfanew + 0x28, NULL, FILE_BEGIN);
    WriteFile(file, pTemp, 4, &dw, 0);
    CloseHandle(file);
    return true;
}
