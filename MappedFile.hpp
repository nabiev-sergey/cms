#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <fcntl.h>
#include <io.h>

class MappedFile {
    LPCTSTR fileName;
    HANDLE hFile;
    HANDLE hMapping;
    LPVOID lpData;
    DWORD size;

    private:
        LPVOID createData();
    public:
        MappedFile(LPCTSTR fileName);
        MappedFile(LPCTSTR fileName, DWORD size);
        ~MappedFile();
        LPVOID getData();
        DWORD getSize();
        void setSize(DWORD size);
};

class MappedFileException : public std::exception {
private:
    MappedFile *mappedFile;
public:
    MappedFileException(MappedFile *mappedFile, char * msg) : exception(msg) {
        this->mappedFile = mappedFile;
    }
    MappedFile *getMappedFile() {
        return mappedFile;
    }
};

class WinApiMappedFileException : public MappedFileException {
private:    
    DWORD lastError;
public:
    WinApiMappedFileException(MappedFile *mappedFile, DWORD lastError, char * msg) : MappedFileException(mappedFile, msg) {
        this->lastError = lastError;
    }
    DWORD getLastError() {
        return lastError;
    }
};
