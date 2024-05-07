#include <tchar.h>
#include <windows.h>
#include <stdexcept>
#include "Thumbprint.hpp"

Thumbprint::Thumbprint(_TCHAR *hex) {
    this->hex = hex;
}

_TCHAR* Thumbprint::getHex() {
    return hex;
}

BYTE digit(_TCHAR c) {
    switch (c) {
        case _T('0') : return 0;
        case _T('1') : return 1;
        case _T('2') : return 2;
        case _T('3') : return 3;
        case _T('4') : return 4;
        case _T('5') : return 5;
        case _T('6') : return 6;
        case _T('7') : return 7;
        case _T('8') : return 8;
        case _T('9') : return 9;
        case _T('a') : return 10;
        case _T('b') : return 11;
        case _T('c') : return 12;
        case _T('d') : return 13;
        case _T('e') : return 14;
        case _T('f') : return 15;
        case _T('A') : return 10;
        case _T('B') : return 11;
        case _T('C') : return 12;
        case _T('D') : return 13;
        case _T('E') : return 14;
        case _T('F') : return 15;
    }
    throw std::exception("not hex digit");
    return 0;
}

DWORD decodeHex(_TCHAR* hex, BYTE* bytes) {
    size_t hexLen = _tcslen(hex);
    DWORD count = 0;
    bool newByte = true;
    while(*hex) {
        if (newByte) {
            newByte = false;
            if (bytes != NULL) {
                *bytes = digit(*hex);
                *bytes <<= 4;
            }
            count++;
        } else {
            if (bytes != NULL) {
                *bytes |= digit(*hex);
                bytes++;
            }
            newByte = true;
        }
        hex++;
    }
    return count;
}

CRYPT_HASH_BLOB* Thumbprint::createCryptHashBlob() {
    DWORD size = decodeHex(hex, NULL);
    BYTE* bytes = new BYTE[size];
    decodeHex(hex, bytes);
    return new CRYPT_HASH_BLOB { size, bytes };
}
