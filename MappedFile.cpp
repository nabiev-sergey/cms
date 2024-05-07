#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <fcntl.h>
#include <io.h>
#include <stdexcept>
#include "MappedFile.hpp"

HANDLE createFile(LPCTSTR fileName, bool readonly) {
    if (readonly) return CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hFile = CreateFile(fileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) SetEndOfFile(hFile);
    return hFile;
}

HANDLE createFileMapping(HANDLE hFile, bool readonly, DWORD size) {
    if (readonly) return CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, size, NULL);
    return CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, size, NULL);
}

LPVOID mapViewOfFile(HANDLE hMapping, bool readonly) {
    if (readonly) return MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    return MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
}

LPVOID MappedFile::createData() {
    bool readonly = (size == 0);
    hFile = createFile(fileName, readonly);
    if (hFile == INVALID_HANDLE_VALUE) throw WinApiMappedFileException(this, GetLastError(), "CreateFile failed");
    if (size == 0) {
        LARGE_INTEGER fileSize;
        GetFileSizeEx(hFile, &fileSize);
        if (fileSize.HighPart != 0) throw MappedFileException(this, "File too long");
        size = fileSize.LowPart;
    }
    hMapping = createFileMapping(hFile, readonly, size);
    if (hMapping == INVALID_HANDLE_VALUE) throw WinApiMappedFileException(this, GetLastError(), "CreateFileMapping failed");    
    return mapViewOfFile(hMapping, readonly);
}

MappedFile::MappedFile(LPCTSTR fileName) {
    this->fileName = fileName;
    this->hFile = INVALID_HANDLE_VALUE;
    this->hMapping = INVALID_HANDLE_VALUE;
    this->lpData = NULL;
    this->size = 0;
}

MappedFile::MappedFile(LPCTSTR fileName, DWORD size) {
    this->fileName = fileName;
    this->hFile = INVALID_HANDLE_VALUE;
    this->hMapping = INVALID_HANDLE_VALUE;
    this->lpData = NULL;
    this->size = size;
}

MappedFile::~MappedFile() {
    if (lpData != NULL) UnmapViewOfFile(lpData);
    if (hMapping != INVALID_HANDLE_VALUE) CloseHandle(hMapping);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
}

LPVOID MappedFile::getData() {
    if (lpData == NULL) {
        lpData = createData();
        if (lpData == NULL) throw WinApiMappedFileException(this, GetLastError(), "MapViewOfFile failed");
    }
    return lpData;
}

DWORD MappedFile::getSize() {
    getData(); // ensure data
    return size;
}

void MappedFile::setSize(DWORD size) {
    this->size = size;
}
