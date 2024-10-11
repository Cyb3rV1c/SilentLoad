/*
 * Author: Cyb3rV1c
 * Created: October 2024
 * Description: Reflective DLL Loader program, made to load dll in memory with a little bit of obfuscation
   to slow down static code analysis.
 * License: MIT License
 *
 * This code was written by Cyb3rV1c and is a work in progress for cybersecurity
 * educational purposes. Unauthorized use or distribution is not allowed without
 * proper credit.
 */

#include <iostream>
#include <Windows.h>

 // Structures
typedef struct OBF_BASE_BLOCK {
    DWORD pagdg;
    DWORD bsg3wf;
} OBF_BASE_BLOCK, * POBF_BASE_BLOCK;

typedef struct OBF_BASE_ENTRY {
    USHORT OBF_Offset : 12;
    USHORT tgdabb : 4;
} OBF_BASE_ENTRY, * POBF_BASE_ENTRY;

using OBF_DLLEntry = BOOL(WINAPI*)(HINSTANCE OBF_dll, DWORD OBF_reason, LPVOID OBF_reserved);

// Main Function
int main() {
    // Get this module's image base address
    PVOID OBF_imageBase = GetModuleHandleA(NULL);

    // Load DLL into memory
    HANDLE fjamsmcnabf = CreateFileA("pathtodll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL); // <---- ADD Path to your dll
    DWORD64 ssf222sfx = GetFileSize(fjamsmcnabf, NULL);
    LPVOID gasc21fcs = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ssf222sfx);
    DWORD fasg2vgas = 0;
    ReadFile(fjamsmcnabf, gasc21fcs, ssf222sfx, &fasg2vgas, NULL);

    // Get pointers to in-memory DLL headers
    PIMAGE_DOS_HEADER ghhbvvaf = (PIMAGE_DOS_HEADER)gasc21fcs;
    PIMAGE_NT_HEADERS ggast3fa = (PIMAGE_NT_HEADERS)((DWORD_PTR)gasc21fcs + ghhbvvaf->e_lfanew);
    SIZE_T hhdsgvvs = ggast3fa->OptionalHeader.SizeOfImage;

    // Allocate new memory space for the DLL
    LPVOID hjgfdbbff = VirtualAlloc((LPVOID)ggast3fa->OptionalHeader.ImageBase, hhdsgvvs, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Get delta between this module's image base and the DLL that was read into memory
    DWORD_PTR jjjggggbbb = (DWORD_PTR)hjgfdbbff - (DWORD_PTR)ggast3fa->OptionalHeader.ImageBase;

    // Copy over DLL image headers to the newly allocated space for the DLL
    std::memcpy(hjgfdbbff, gasc21fcs, ggast3fa->OptionalHeader.SizeOfHeaders);

    // Copy over DLL image sections to the newly allocated space for the DLL
    PIMAGE_SECTION_HEADER vffhfhf = IMAGE_FIRST_SECTION(ggast3fa);
    for (size_t ifasfas = 0; ifasfas < ggast3fa->FileHeader.NumberOfSections; ifasfas++) {
        LPVOID Dgdagdsa = (LPVOID)((DWORD_PTR)hjgfdbbff + (DWORD_PTR)vffhfhf->VirtualAddress);
        LPVOID Sgdgdgg = (LPVOID)((DWORD_PTR)gasc21fcs + (DWORD_PTR)vffhfhf->PointerToRawData);
        std::memcpy(Dgdagdsa, Sgdgdgg, vffhfhf->SizeOfRawData);
        vffhfhf++;
    }

    // Perform image base relocations
    IMAGE_DATA_DIRECTORY ragdadg = ggast3fa->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD_PTR rtgdgg = ragdadg.VirtualAddress + (DWORD_PTR)hjgfdbbff;
    DWORD rpgasggg = 0;

    while (rpgasggg < ragdadg.Size) {
        POBF_BASE_BLOCK rbhdddxx = (POBF_BASE_BLOCK)(rtgdgg + rpgasggg);
        rpgasggg += sizeof(OBF_BASE_BLOCK);
        DWORD rchhdddc = (rbhdddxx->bsg3wf - sizeof(OBF_BASE_BLOCK)) / sizeof(OBF_BASE_ENTRY);
        POBF_BASE_ENTRY rehhccc = (POBF_BASE_ENTRY)(rtgdgg + rpgasggg);

        for (DWORD i34t6g = 0; i34t6g < rchhdddc; i34t6g++) {
            rpgasggg += sizeof(OBF_BASE_ENTRY);

            if (rehhccc[i34t6g].tgdabb == 0) {
                continue;
            }

            DWORD_PTR rrgvddd = rbhdddxx->pagdg + rehhccc[i34t6g].OBF_Offset;
            DWORD_PTR atpgdga = 0;
            ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)hjgfdbbff + rrgvddd), &atpgdga, sizeof(DWORD_PTR), NULL);
            atpgdga += jjjggggbbb;
            std::memcpy((PVOID)((DWORD_PTR)hjgfdbbff + rrgvddd), &atpgdga, sizeof(DWORD_PTR));
        }
    }

    // IAT Resolve
    PIMAGE_IMPORT_DESCRIPTOR iDvgsaf = NULL;
    IMAGE_DATA_DIRECTORY idgasgs = ggast3fa->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    iDvgsaf = (PIMAGE_IMPORT_DESCRIPTOR)(idgasgs.VirtualAddress + (DWORD_PTR)hjgfdbbff);
    LPCSTR lngg = "";
    HMODULE lhhh = NULL;

    while (iDvgsaf->Name != NULL) {
        lngg = (LPCSTR)iDvgsaf->Name + (DWORD_PTR)hjgfdbbff;
        lhhh = LoadLibraryA(lngg);

        if (lhhh) {
            PIMAGE_THUNK_DATA thhhg = NULL;
            thhhg = (PIMAGE_THUNK_DATA)((DWORD_PTR)hjgfdbbff + iDvgsaf->FirstThunk);

            while (thhhg->u1.AddressOfData != NULL) {
                if (IMAGE_SNAP_BY_ORDINAL(thhhg->u1.Ordinal)) {
                    LPCSTR foggx = (LPCSTR)IMAGE_ORDINAL(thhhg->u1.Ordinal);
                    thhhg->u1.Function = (DWORD_PTR)GetProcAddress(lhhh, foggx);
                }
                else {
                    PIMAGE_IMPORT_BY_NAME fnjftg = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)hjgfdbbff + thhhg->u1.AddressOfData);
                    DWORD_PTR fhgdd = (DWORD_PTR)GetProcAddress(lhhh, fnjftg->Name);
                    thhhg->u1.Function = fhgdd;
                }
                ++thhhg;
            }
        }

        iDvgsaf++;
    }

    // Loaded DLL Execution
    OBF_DLLEntry OBF_DllEntry = (OBF_DLLEntry)((DWORD_PTR)hjgfdbbff + ggast3fa->OptionalHeader.AddressOfEntryPoint);
    (*OBF_DllEntry)((HINSTANCE)hjgfdbbff, DLL_PROCESS_ATTACH, 0);

    CloseHandle(fjamsmcnabf);
    HeapFree(GetProcessHeap(), 0, gasc21fcs);

    return 0;
}
