
<p align="center"> <img width="349" alt="silentload" src="https://github.com/user-attachments/assets/f028dfb7-bc60-4a2b-aa44-86b0671a2732"> </p>

A reflective DLL loader that injects a DLL containing XOR-encrypted shellcode into memory, bypassing traditional loading methods. 
The payload is decrypted and executed dynamically, featuring anti-analysis techniques to evade detection.




# Features

**[+] Obfuscation Techniques:** Employs XOR encryption to avoid signature-based detection.

**[+] Memory Injection:** Allocates and manipulates memory for shellcode injection.

**[+] Reflective DLL Loading :** The DLL is manually mapped into a process's memory space, allowing it to bypass detection by antivirus and security tools, as it avoids writing the file to disk.




# Getting Started

**Installation**


1. Clone the repository:
```
git clone https://github.com/Cyb3rV1c/SilentLoad
```


# Usage

**1.** Encrypt your generated shellcode in Xor, you can use [Xor_Encryptor ](https://github.com/Cyb3rV1c/Phantom/tree/main/Xor_Encryptor)

**2.** Copy your shellcode into the payload Dll "funproject.sln"
   
***Notice*** Make sure to add in the project the same xor key that you encrypted your shellcode with.

**3.** Build the Dll

**4.** Specify the Dll's path in SilentLoad.sln & build it. 



***Notice***: Make sure your shellcode has the same architecture as the environment you'll execute it in.

# Example Output



# Technical Details


**Shellcode Injection:**
Will use VirtualAlloc() to allocate the memory with the arguments MEM_RESERVE, PAGE_READWRITE but the execution part will be passed to VirtualProtect, this way adds a bit of stealthiness,
instead of having VirtualAlloc executing the shellcode, which is often seen in the field.

**XOR Encryption/Decryption:**
A simple XOR-based decryption routine is used to deobfuscate the shellcode before injection, providing a layer of evasion from static analysis.

**Reflective Loading:** The SilentLoad, triggered by shellcode or CreateRemoteThread(), finds its memory location, resolves essential functions (LoadLibraryA, GetProcAddress, VirtualAlloc), and allocates space for the DLL. 
It then relocates the DLL, resolves imports, and calls the entry point (DllMain). Once loaded, it returns control to the initial shellcode or terminates the remote thread.







# Disclaimer
**This project is intended for educational and research purposes only.**

The code provided in this repository is designed to help individuals understand and improve their knowledge of cybersecurity, ethical hacking, and malware analysis techniques. 
It must not be used for malicious purposes or in any environment where you do not have explicit permission from the owner.
