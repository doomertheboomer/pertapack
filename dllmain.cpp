// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <stdio.h>
#include <map>
#include <vector>
#include <openssl/ssl.h>
#include "MinHook/include/MinHook.h"

// hardcoded key and IV, change to your liking
const unsigned char* key = reinterpret_cast<const unsigned char*>("01234567890123456789012345678901");
const unsigned char* iv = reinterpret_cast<const unsigned char*>("xxxxPERTAPCKxxxx");

// table to keep track of opened files to prevent memleak
std::map<HANDLE, std::vector<unsigned char>> openFiles;

int encryptAES(const unsigned char* plaintext, int plaintext_len, const unsigned char* key,
    const unsigned char* iv, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decryptAES(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key,
    const unsigned char* iv, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

typedef BOOL(WINAPI* PReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
PReadFile orig_ReadFile;
BOOL WINAPI hook_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    puts("ReadFile hook hit!");

    // check if file is part of encrypted files map
    auto it = openFiles.find(hFile);
    if (it != openFiles.end()) {
        puts("Reading PertaPacked file");
        // get file offset for returning
        int offset = 0;
        if (lpOverlapped) {
            offset = lpOverlapped->Offset;
            
            lpOverlapped->Internal = 0;
            lpOverlapped->InternalHigh = nNumberOfBytesToRead;

            if (lpOverlapped->hEvent != NULL) {
                SetEvent(lpOverlapped->hEvent);
            }
        }
        else {
            offset = SetFilePointer(hFile, 0, nullptr, FILE_CURRENT);
        }
        memcpy(lpBuffer, it->second.data() + offset, nNumberOfBytesToRead);
        return TRUE;
    }

    return orig_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}


typedef BOOL(WINAPI* PCloseHandle)(HANDLE hObject);
PCloseHandle orig_CloseHandle;
BOOL WINAPI hook_CloseHandle(HANDLE hObject) {
    puts("CloseHandle hook hit!");

    // look for handle in openFiles map and delete it
    auto it = openFiles.find(hObject);
    if (it != openFiles.end()) {
        puts("Deleting PertaPacked file handle");
        it->second.clear();
        openFiles.erase(it);
    }

    return orig_CloseHandle(hObject);
}

void processFile(HANDLE hFile, DWORD dwFlagsAndAttributes) {
    // TODO: process overlapped CreateFiles

    // get file size (max size is 32bit int limit)
    LARGE_INTEGER size;
    GetFileSizeEx(hFile, &size);
    DWORD fileSize = size.LowPart;
    if (fileSize < 13) { return; }

    // actually read the file
    char* buffer = new char[fileSize];
    DWORD bytesRead;
    if ((dwFlagsAndAttributes & FILE_FLAG_OVERLAPPED) != 0) {
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        OVERLAPPED overlapped = {};
        overlapped.Offset = 0;
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!orig_ReadFile(hFile, buffer, fileSize, nullptr, &overlapped)) {
            DWORD error = GetLastError();
            if (error == ERROR_IO_PENDING) {
                WaitForSingleObject(overlapped.hEvent, INFINITE);
                GetOverlappedResult(hFile, &overlapped, &bytesRead, TRUE);
            }
            else {
                delete[] buffer;
                orig_CloseHandle(overlapped.hEvent);
                return;
            }
        }
        orig_CloseHandle(overlapped.hEvent);
    }
    else {
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        orig_ReadFile(hFile, buffer, fileSize, nullptr, nullptr);
    }

    // decryption logic goes here
    // check if file is pertapacked
    if (memcmp(buffer, "PTPCK", 5) == 0) {
        puts("File is PertaPacked");
        // perform decryption
        int fileCrc32 = 0;
        int decSize = 0;

        // get decrypted file properties
        memcpy(&fileCrc32, buffer + 5, sizeof(fileCrc32));
        memcpy(&decSize, buffer + 9, sizeof(decSize));

        // make a buffer with headers stripped out and init output buffer
        const unsigned char* aesData = reinterpret_cast<unsigned char*>(buffer + 13);
        int aesDataLen = fileSize - 13;
        unsigned char* decryptedData = new unsigned char[decSize];

        // decrypt the file and store in buffer
        int decryptedLen = decryptAES(aesData, aesDataLen, key, iv, decryptedData);
        std::vector<unsigned char> decryptedBuffer(decryptedData, decryptedData + decryptedLen);
        openFiles[hFile] = decryptedBuffer;

        // clean up
        delete[] decryptedData;
    }
    delete[] buffer;
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
}

// process encrypted files as they are opened
typedef HANDLE(WINAPI* PCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
PCreateFileA orig_CreateFileA;
HANDLE WINAPI hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    puts("CreateFileA hook hit!");
    auto retVal = orig_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    if (retVal != INVALID_HANDLE_VALUE) {
        processFile(retVal, dwFlagsAndAttributes);
    }
    return retVal;
}
typedef HANDLE(WINAPI* PCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
PCreateFileW orig_CreateFileW;
HANDLE WINAPI hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    puts("CreateFileW hook hit!");
    auto retVal = orig_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    if (retVal != INVALID_HANDLE_VALUE) {
        processFile(retVal, dwFlagsAndAttributes);
    }
    return retVal;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MH_Initialize();
        
        MH_CreateHookApi(L"Kernel32.dll", "ReadFile", hook_ReadFile, (void**)&orig_ReadFile);
        MH_CreateHookApi(L"Kernel32.dll", "CloseHandle", hook_CloseHandle, (void**)&orig_CloseHandle);
        MH_CreateHookApi(L"Kernel32.dll", "CreateFileA", hook_CreateFileA, (void**)&orig_CreateFileA);
        MH_CreateHookApi(L"Kernel32.dll", "CreateFileW", hook_CreateFileW, (void**)&orig_CreateFileW);
        
        MH_EnableHook(MH_ALL_HOOKS);
        puts("PertaPack Loaded!");

        break;
    }
    return TRUE;
}

