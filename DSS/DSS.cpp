#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>
#include <iostream>
#include <chrono>
#include <algorithm>
#include <iterator>
#include <string>

#define BUFFER_SIZE 1<<10
#pragma comment (lib, "advapi32.lib")

void GenerateKey(){
    DWORD dwBlobLen = 0;
    BYTE* pbKeyBlob = nullptr;
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_DSS_DH, 0) && !CryptAcquireContext(&hProv, NULL, NULL, PROV_DSS_DH, CRYPT_NEWKEYSET)) {
        std::cout << "Unable to create context\n";
        return;
    }
    DWORD flags = 1024;
    flags |= CRYPT_EXPORTABLE;
    if (CryptGenKey(hProv, AT_SIGNATURE, CRYPT_EXPORTABLE, &hKey)) {
        printf("A key has been created.\n");
    }

    if (CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
        printf("Size of the BLOB for the public key determined. \n");
    }
    else {
        puts("Error computing BLOB length.");
    }

    pbKeyBlob = new BYTE[dwBlobLen];

    if (CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen)) {
        printf("Contents have been written to the BLOB. \n");
    }
    else {
        puts("Error during CryptExportKey.");
    }

    HANDLE hKeyFile;
    if ((hKeyFile = CreateFileA("key.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) {
        if (!WriteFile(hKeyFile, pbKeyBlob, dwBlobLen, &dwBlobLen, NULL))
            std::cout << "Unable to save RSA key in file\n";
        CloseHandle(hKeyFile);
    }
    else
        std::cout << "Unable to create key file\n";
    CryptDestroyKey(hKey);  
}

void Sign(const char* _InFile, const char* _KeyFile, char mode, std::string str = "") {
    HCRYPTPROV hProv;
    HCRYPTKEY hPubKey = 0;
    DWORD dwSigLen;
    BYTE* pbSignature = nullptr;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_DSS_DH, 0)) {
        printf("CSP context acquired.\n");
        HCRYPTHASH hHash;
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            printf("Hash object created. \n");
            HANDLE hInFile;
            BYTE buf[BUFFER_SIZE];
            if (!str.empty()) {
                int size = str.length();
                strcpy((char*)buf, str.c_str());
                if (CryptHashData(hHash, buf, BUFFER_SIZE, 0)) {
                    //printf("The data buffer has been hashed.\n");
                }
                else {
                    puts("Error during CryptHashData.");
                }
                std::cout << buf;
            }
            else {
                if ((hInFile = CreateFileA(_InFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) {
                    long long dwFileSize = GetFileSize(hInFile, NULL);
                    DWORD dwSigLen = 0;
                        while (dwFileSize > 0) {
                            if (!ReadFile(hInFile, buf, BUFFER_SIZE, &dwSigLen, NULL)) {
                                std::cout << "Read error\n";
                                break;
                            }

                            if (CryptHashData(hHash, buf, BUFFER_SIZE, 0)) {
                                //printf("The data buffer has been hashed.\n");
                            }
                            else {
                                puts("Error during CryptHashData.");
                            }
                            dwFileSize -= BUFFER_SIZE;
                        }
                        std::cout << "The data buffer has been hashed\n";
                    CloseHandle(hInFile);
                }
                else {
                    std::cout << "Can`t open input file\n";
                    return;
                }
                    
            }
            switch (mode) {
                case 's':{
                    if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen)) {
                        printf("Signature length %d found.\n", dwSigLen);
                    }
                    else {
                        puts("Error during CryptSignHash.");
                    }

                    if (pbSignature = new BYTE[dwSigLen]) {
                        printf("Memory allocated for the signature.\n");
                    }
                    else {
                        puts("Out of memory.");
                    }

                    if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen)) {
                        printf("pbSignature is the hash signature.\n");
                    }
                    else {
                        puts("Error during CryptSignHash.");
                    }

                    printf("The signing phase of this program is completed.\n\n");
                    HANDLE hSignFile;
                    if ((hSignFile = CreateFileA("signature.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL)) != INVALID_HANDLE_VALUE) {
                        if (!WriteFile(hSignFile, pbSignature, dwSigLen, &dwSigLen, NULL)) {
                            std::cout << "Write error\n";
                        }
                        std::cout << "Signature is:";
                        for (int i = 0; i < dwSigLen; i++) {
                            std::cout << pbSignature[i];
                        }
                        std::cout << std::endl;
                        CloseHandle(hSignFile);
                    }
                    break;
                }
                case 'c': {
                    HANDLE hKeyFile;
                    DWORD dwBlobLen = 0;
                    BYTE* pbKeyBlob = nullptr;
                    if ((hKeyFile = CreateFileA(_KeyFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) {
                        dwBlobLen = GetFileSize(hKeyFile, NULL);
                        pbKeyBlob = new BYTE[dwBlobLen];
                        ReadFile(hKeyFile, pbKeyBlob, dwBlobLen, &dwBlobLen, NULL);
                        CloseHandle(hKeyFile);
                    }
                    else {
                        std::cout << "Can`t open key file\n";
                        return;
                    }

                    if (CryptImportKey(hProv, pbKeyBlob, dwBlobLen, hPubKey, 0, &hPubKey)) {
                        printf("The key has been imported.\n");
                    }
                    else {
                        puts("Public key import failed.");
                    }


                    HANDLE hSignFile;
                    if ((hSignFile = CreateFileA("signature.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) {
                        dwSigLen = GetFileSize(hSignFile, NULL);
                        pbSignature = new BYTE[dwSigLen];
                        if (!ReadFile(hSignFile, pbSignature, dwSigLen, &dwSigLen, NULL)) {
                            std::cout << "Read error\n";
                        }
                        CloseHandle(hSignFile);
                    }
                    else {
                        std::cout << "Can`t open signature file\n";
                        return;
                    }

                    if (CryptVerifySignature(hHash, pbSignature, dwSigLen, hPubKey, NULL, 0)) {
                        printf("The signature has been verified.\n");
                    }
                    else {
                        printf("Signature not validated!\n");
                    }

                    CryptDestroyKey(hPubKey);
                    break;
                }
            }
            if (pbSignature) {
               delete [] pbSignature;
            }

            if (hHash) {
                CryptDestroyHash(hHash);
            }

            if (hProv) {
                CryptReleaseContext(hProv, 0);
            }
        }
        else {
            puts("Error during CryptCreateHash.");
        }
    }
    else {
        puts("Error during CryptAcquireContext.");
    }
}

int main(){
    int choise = 0;
    while (choise != -1) {
        std::cout << "1-Sign\n2-Check\n3-Generate key\n";
        std::cin >> choise;
        std::string str,file,key;
        switch (choise) {
            case 1:
                getchar();
                std::cout << "File to sign: ";
                getline(std::cin, file);
                std::cout << "str to sign: ";
                getline(std::cin, str);
                Sign(file.c_str(), key.c_str(), 's', str);
                break;
            case 2:
                getchar();
                std::cout << "key file: ";
                getline(std::cin, key);
                std::cout << "File to check: ";
                getline(std::cin, file);
                std::cout << "str to sign: ";
                getline(std::cin, str);
                Sign(file.c_str(), key.c_str(), 'c', str);
                break;
            case 3:
                getchar();
                GenerateKey();
                break;
        }
    }
    return 0;
}
