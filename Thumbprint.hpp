#include <tchar.h>
#include <windows.h>
#include <memory>

class Thumbprint {
private:
    _TCHAR* hex;
public:
    Thumbprint(_TCHAR *hex);
    _TCHAR* getHex();
    CRYPT_HASH_BLOB* createCryptHashBlob();
};
