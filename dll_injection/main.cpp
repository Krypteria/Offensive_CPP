#include <windows.h>
#include <stdio.h>

const char* ok = "[+]";
const char* info = "[*]";
const char* err = "[-]";

int main(int argc, char* argv[]){

    if(argc != 3){
        printf("%s Usage: %s <PID> <DLL ABSOLUTE PATH>", err, argv[0]);
        return EXIT_FAILURE;
    }

    const DWORD pid = atoi(argv[1]);
    const char* dllPath = argv[2];

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if(hProcess == NULL){
        printf("\n%s Cannot open handle to the process\n", err);
        return EXIT_FAILURE;
    } 

    printf("\n%s Handle to the process obtained\n", ok);

    
    LPVOID bAddress = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(bAddress == NULL){
        printf("%s Cannot allocate memory for the dll\n", err);
        return EXIT_FAILURE;
    }

    printf("%s Memory allocated succesfully\n", ok);

    if(WriteProcessMemory(hProcess, bAddress, dllPath, strlen(dllPath) + 1, NULL) == 0){
        printf("%s Cannot write on memory, error %d", err, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s Memory written succesfully\n", ok);

    HANDLE hRemote = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), bAddress, 0, NULL);
    if(hRemote == NULL){
        printf("%s Cannot get the handle to the remote process\n", err);
        return EXIT_FAILURE;
    }
    
    printf("%s Remote thread executed succesfully\n", ok);

    CloseHandle(hProcess);
    CloseHandle(hRemote);

    return EXIT_SUCCESS;
}