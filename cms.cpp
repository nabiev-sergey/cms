//-------------------------------------------------------------------
//   Copyright (C) Microsoft.  All rights reserved.

#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <fcntl.h>
#include <io.h>
#include <functional>
#include <memory>
#include "cmsexcept.hpp"
#include "MappedFile.hpp"
#include "Thumbprint.hpp"

// Link with the Crypt32.lib file.
#pragma comment (lib, "Crypt32")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

//-------------------------------------------------------------------
//    Define the name of the store where the needed certificate
//    can be found. 

#define CERT_STORE_NAME  L"MY"

class CertQuery {
private:
    DWORD flags;        
    CRYPT_HASH_BLOB* cryptHashBlob;
public:
    CertQuery(DWORD flags, CRYPT_HASH_BLOB* cryptHashBlob) : flags(flags), cryptHashBlob(cryptHashBlob) { }
    ~CertQuery() { 
        if (cryptHashBlob == NULL) return;
        if (cryptHashBlob->pbData != NULL) delete [] cryptHashBlob->pbData;
        delete cryptHashBlob;
    }
    DWORD getFlags() { return flags; }
    CRYPT_HASH_BLOB* getCryptHashBlob() { return cryptHashBlob; }
};

//-------------------------------------------------------------------
//   Local function prototypes.
void MyHandleError(LPTSTR psz);
void SignMessage(bool detached, const BYTE* rgpbToBeSigned, DWORD rgcbToBeSigned, CertQuery& certQuery, std::function<BYTE*(DWORD)> allocSignatureBytes);

bool startWith(const LPTSTR str, const LPTSTR prefix) {
    TCHAR* strChar = str;
    TCHAR* prefixChar = prefix;
    while (*prefixChar) {
        if (*prefixChar != *strChar) return false;
        prefixChar++;
        strChar++;
    }
    return true;
}

CRYPT_HASH_BLOB* toCryptHashBlob(LPTSTR hex) {
    Thumbprint thumbprint(hex);
    return thumbprint.createCryptHashBlob();
}

CertQuery* toCertQuery(LPTSTR query) {
    if (startWith(query, TEXT("machine/"))) {
        return new CertQuery(CERT_SYSTEM_STORE_LOCAL_MACHINE, toCryptHashBlob(query + 8));
    } else if (startWith(query, TEXT("user/"))) {
        return new CertQuery(CERT_SYSTEM_STORE_CURRENT_USER, toCryptHashBlob(query + 5));
    }
    return new CertQuery(CERT_SYSTEM_STORE_LOCAL_MACHINE, toCryptHashBlob(query));
}

int _tmain(int argc, _TCHAR* argv[]) {
//    UNREFERENCED_PARAMETER(argc);
//    UNREFERENCED_PARAMETER(argv);

    if (argc < 2) {
        MyHandleError(TEXT("cms [+|-|attach|detach] [user/|machine/]signer_cert_thumbprint signed_file signature_file"));
        return 1;
    }

    int argBase = 1;
    bool detached = true;
    if (_tcscmp(TEXT("attach"), argv[1]) == 0) {
        detached = false;
        argBase = 2;
    } else if (_tcscmp(TEXT("+"), argv[1]) == 0) {
        detached = false;
        argBase = 2;
    } else if (_tcscmp(TEXT("detach"), argv[1]) == 0) {
        detached = true;
        argBase = 2;
    } else if (_tcscmp(TEXT("-"), argv[1]) == 0) {
        detached = true;
        argBase = 2;
    }

    if (argc < argBase + 3) {
        MyHandleError(TEXT("cms [+|-|attach|detach] signer_cert_thumbprint signed_file signature_file"));
        return 1;
    }

    try {
        std::unique_ptr<CertQuery> certQueryPtr(toCertQuery(argv[argBase + 0]));

        LPCTSTR lpSignedFileName = argv[argBase + 1];
        MappedFile signedMappedFile = MappedFile(lpSignedFileName);

        LPCTSTR lpSignatureFileName = argv[argBase + 2];
        MappedFile signatureMappedFile = MappedFile(lpSignatureFileName);

        SignMessage(detached, (BYTE*) signedMappedFile.getData(), signedMappedFile.getSize(), *certQueryPtr.get(), [&](DWORD size) -> BYTE* {
            signatureMappedFile.setSize(size);
            return (BYTE*) signatureMappedFile.getData();
        });
    } catch(std::exception &ex) {
        fprintf(stderr, "Signing failed. Reason: %s\n", ex.what());
        return 2;
    } catch(...) {
        fprintf(stderr, "Signing failed. Reason: unknown\n");
        return 3;
    }
        fprintf(stderr, "Signing successfull\n");
    return 0;
}

//-------------------------------------------------------------------
//    MyHandleError
void MyHandleError(LPTSTR psz) {
    _ftprintf(stderr, TEXT("An error occurred in the program.\n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
//    _ftprintf(stderr, TEXT("Program terminating.\n"));
} // End of MyHandleError

#define OID_GOST3410_12_256 "1.2.643.7.1.1.1.1"
#define OID_GOST3410_12_512 "1.2.643.7.1.1.1.2"

#define OID_CSP2012_HASH_256 "1.2.643.7.1.1.2.2"
#define OID_CSP2012_HASH_512 "1.2.643.7.1.1.2.3"

CRYPT_ALGORITHM_IDENTIFIER CSP2012_HASH_256 = {
    OID_CSP2012_HASH_256,
    {NULL}
};

CRYPT_ALGORITHM_IDENTIFIER CSP2012_HASH_512 = {
    OID_CSP2012_HASH_512,
    {NULL}
};

PCRYPT_ALGORITHM_IDENTIFIER HashAlgorithm(PCCERT_CONTEXT pSignerCert) {
    LPSTR pszPubKeyAlg = pSignerCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    if (strcmp(OID_GOST3410_12_256, pszPubKeyAlg) == 0) return &CSP2012_HASH_256;
    if (strcmp(OID_GOST3410_12_512, pszPubKeyAlg) == 0) return &CSP2012_HASH_512;
    return NULL;
}

struct SignResources {
    HCERTSTORE hCertStore;
    PCCERT_CONTEXT pSignerCert;
    SignResources() {
        hCertStore = NULL;
        pSignerCert = NULL;
    }
    ~SignResources() {
        if(pSignerCert) {
            CertFreeCertificateContext(pSignerCert);
        }
        if(hCertStore) {
            CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
        }
    }
};

//-------------------------------------------------------------------
//    SignMessage
void SignMessage(bool detached, const BYTE * rgpbToBeSigned, DWORD rgcbToBeSigned, CertQuery& certQuery, std::function<BYTE*(DWORD)> allocSignatureBytes) {
    bool fReturn = false;
    SignResources resources;
    CRYPT_SIGN_MESSAGE_PARA  SigParams;
    DWORD cbSignedMessageBlob;
    BYTE  *pbSignedMessageBlob = NULL;
    CRYPT_DATA_BLOB signedMessageBlob = { 0, NULL };

    // Create the MessageArray and the MessageSizeArray.
    const BYTE* MessageArray[] = { rgpbToBeSigned };
    DWORD MessageSizeArray[] = { rgcbToBeSigned };

    // Open the certificate store.
    if (!(resources.hCertStore = CertOpenStore(
       CERT_STORE_PROV_SYSTEM,
       0,
       NULL,
       certQuery.getFlags(),
       CERT_STORE_NAME)))
    {
        throw cmsexcept("The MY store could not be opened.");
    }

    // Get a pointer to the signer's certificate.
    // This certificate must have access to the signer's private key.
    if(!(resources.pSignerCert = CertFindCertificateInStore(
       resources.hCertStore,
       MY_ENCODING_TYPE,
       0,
       CERT_FIND_SHA1_HASH,
       certQuery.getCryptHashBlob(),
       NULL)))
    {
        throw cmsexcept("Signer certificate not found.");
    }

    // Initialize the signature structure.
    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    SigParams.pSigningCert = resources.pSignerCert;

    PCRYPT_ALGORITHM_IDENTIFIER pHashAlgorithm = HashAlgorithm(resources.pSignerCert);
    if (pHashAlgorithm == NULL) throw cmsexcept("Can't determine hash algorithm.");
    SigParams.HashAlgorithm = *pHashAlgorithm;
    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &resources.pSignerCert;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;

    // First, get the size of the signed BLOB.
    if(!CryptSignMessage(
        &SigParams,
        detached ? TRUE : FALSE,
        1,
        MessageArray,
        MessageSizeArray,
        NULL,
        &cbSignedMessageBlob))
    {
        throw cmsexcept("Getting signed BLOB size failed");
    }

    // Allocate memory for the signed BLOB.
    if(!(pbSignedMessageBlob = allocSignatureBytes(cbSignedMessageBlob))) {
        throw cmsexcept("Memory allocation error while signing.");
    }

    // Get the signed message BLOB.
    if(!CryptSignMessage(
          &SigParams,
          detached ? TRUE : FALSE,
          1,
          MessageArray,
          MessageSizeArray,
          pbSignedMessageBlob,
          &cbSignedMessageBlob)) 
    {
       throw cmsexcept("Error getting signed BLOB");
    }
}
