// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo

package client

// The Secure Enclave as the machine key's store (RM-357), through the
// Security framework.
//
// The key is a non-permanent Enclave key: it is not put in any keychain.
// What the Enclave hands back is its own wrapped handle to the key (the
// token object id, the same bytes CryptoKit calls a Secure Enclave key's
// dataRepresentation). The handle is written to key.se; only this Mac's
// Enclave can unwrap it, and no call exports the private key from it.
//
// Why not a keychain item: a permanent Enclave key lives in the data
// protection keychain, which needs a keychain-access-groups entitlement
// backed by a provisioning profile. A bare command-line binary signed with
// a Developer ID (scripts/codesign-cli.sh) carries no profile, and the
// keychain answers errSecMissingEntitlement (-34018); measured on the
// operator's Mac with a maintained Go library that only makes permanent
// keys. The handle route needs no entitlement, no profile and no keychain.
//
// No user presence: the access control is kSecAccessControlPrivateKeyUsage
// alone, so every TLS handshake signs without Touch ID. The client service
// runs unattended (a launchd agent) and signs a handshake per connection to
// the core; a prompt each time would stop recording. The key is usable after
// the first unlock since boot, and never on another device
// (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly).
//
// kSecAttrTokenOID is not in the public headers; its value is the string
// "toid", the attribute CryptoKit itself reads and writes.

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

static CFStringRef innseglTokenOID(void) { return CFSTR("toid"); }

// innseglErr is err's code and description; err is released.
static long innseglErr(CFErrorRef err, char **desc) {
	if (err == NULL) {
		return 0;
	}
	long code = (long)CFErrorGetCode(err);
	CFStringRef s = CFErrorCopyDescription(err);
	if (s != NULL) {
		CFIndex n = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
		*desc = malloc((size_t)n);
		if (*desc != NULL && !CFStringGetCString(s, *desc, n, kCFStringEncodingUTF8)) {
			(*desc)[0] = 0;
		}
		CFRelease(s);
	}
	CFRelease(err);
	return code;
}

// innseglGenerate makes a non-permanent P-256 key in the Secure Enclave.
static SecKeyRef innseglGenerate(long *code, char **desc) {
	CFErrorRef err = NULL;
	SecAccessControlRef ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
		kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &err);
	if (ac == NULL) {
		*code = innseglErr(err, desc);
		return NULL;
	}
	CFMutableDictionaryRef priv = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(priv, kSecAttrIsPermanent, kCFBooleanFalse);
	CFDictionarySetValue(priv, kSecAttrAccessControl, ac);
	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	int bits = 256;
	CFNumberRef size = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
	CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, size);
	CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, priv);
	SecKeyRef key = SecKeyCreateRandomKey(attrs, &err);
	CFRelease(size);
	CFRelease(attrs);
	CFRelease(priv);
	CFRelease(ac);
	if (key == NULL) {
		*code = innseglErr(err, desc);
	}
	return key;
}

// innseglHandle is the Enclave's wrapped handle to key, or NULL.
static CFDataRef innseglHandle(SecKeyRef key) {
	CFDictionaryRef attrs = SecKeyCopyAttributes(key);
	if (attrs == NULL) {
		return NULL;
	}
	CFDataRef h = CFDictionaryGetValue(attrs, innseglTokenOID());
	if (h != NULL) {
		CFRetain(h);
	}
	CFRelease(attrs);
	return h;
}

// innseglRestore opens the Enclave key a handle names.
static SecKeyRef innseglRestore(const UInt8 *b, CFIndex n, long *code, char **desc) {
	CFErrorRef err = NULL;
	CFDataRef handle = CFDataCreate(kCFAllocatorDefault, b, n);
	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
	CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(attrs, innseglTokenOID(), handle);
	SecKeyRef key = SecKeyCreateWithData(handle, attrs, &err);
	CFRelease(attrs);
	CFRelease(handle);
	if (key == NULL) {
		*code = innseglErr(err, desc);
	}
	return key;
}

// innseglPublic is key's public half as an uncompressed X9.63 point.
static CFDataRef innseglPublic(SecKeyRef key) {
	SecKeyRef pub = SecKeyCopyPublicKey(key);
	if (pub == NULL) {
		return NULL;
	}
	CFDataRef out = SecKeyCopyExternalRepresentation(pub, NULL);
	CFRelease(pub);
	return out;
}

// innseglSign signs a digest; alg names its hash: 1, 256, 384 or 512.
static CFDataRef innseglSign(SecKeyRef key, int alg, const UInt8 *d, CFIndex n, long *code, char **desc) {
	SecKeyAlgorithm a;
	switch (alg) {
	case 1:   a = kSecKeyAlgorithmECDSASignatureDigestX962SHA1; break;
	case 256: a = kSecKeyAlgorithmECDSASignatureDigestX962SHA256; break;
	case 384: a = kSecKeyAlgorithmECDSASignatureDigestX962SHA384; break;
	default:  a = kSecKeyAlgorithmECDSASignatureDigestX962SHA512; break;
	}
	CFErrorRef err = NULL;
	CFDataRef digest = CFDataCreate(kCFAllocatorDefault, d, n);
	CFDataRef sig = SecKeyCreateSignature(key, a, digest, &err);
	CFRelease(digest);
	if (sig == NULL) {
		*code = innseglErr(err, desc);
	}
	return sig;
}

static void innseglRelease(CFTypeRef r) { if (r != NULL) CFRelease(r); }
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

func platformVault() keyVault { return enclaveVault{} }

// enclaveVault is the Secure Enclave.
type enclaveVault struct{}

func (enclaveVault) name() string { return "Secure Enclave" }

func (enclaveVault) generate() (MachineKey, []byte, error) {
	var code C.long
	var desc *C.char
	ref := C.innseglGenerate(&code, &desc) //nolint:gocritic // cgo's generated call, not a comparison
	if ref == 0 {
		return nil, nil, secError("creating a key in the Secure Enclave", code, desc)
	}
	k, err := newEnclaveKey(ref)
	if err != nil {
		return nil, nil, err
	}
	h := C.innseglHandle(ref)
	if h == 0 {
		return nil, nil, errors.New("the Secure Enclave gave no handle for the new key")
	}
	defer C.innseglRelease(C.CFTypeRef(h))
	return k, cfBytes(h), nil
}

func (enclaveVault) load(blob []byte) (MachineKey, error) {
	if len(blob) == 0 {
		return nil, errors.New("the Secure Enclave handle is empty")
	}
	var code C.long
	var desc *C.char
	ref := C.innseglRestore((*C.UInt8)(unsafe.Pointer(&blob[0])), C.CFIndex(len(blob)), &code, &desc) //nolint:gocritic // cgo's generated call
	if ref == 0 {
		return nil, secError("opening the Secure Enclave key (a handle made on another Mac, or for a key "+
			"the Enclave no longer has, cannot be opened)", code, desc)
	}
	return newEnclaveKey(ref)
}

// enclaveKey is a key held by the Secure Enclave. Its private half never
// leaves the Enclave; Sign asks the Enclave to sign a digest.
type enclaveKey struct {
	ref *secKey
	pub *ecdsa.PublicKey
}

// secKey owns one SecKeyRef, released when it is collected.
type secKey struct{ ref C.SecKeyRef }

func newEnclaveKey(ref C.SecKeyRef) (*enclaveKey, error) {
	owner := &secKey{ref: ref}
	runtime.AddCleanup(owner, func(r C.SecKeyRef) { C.innseglRelease(C.CFTypeRef(r)) }, ref)
	raw := C.innseglPublic(ref)
	if raw == 0 {
		return nil, errors.New("the Secure Enclave key has no readable public key")
	}
	defer C.innseglRelease(C.CFTypeRef(raw))
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), cfBytes(raw))
	if err != nil {
		return nil, fmt.Errorf("the Secure Enclave key's public key is not a P-256 point: %w", err)
	}
	return &enclaveKey{ref: owner, pub: pub}, nil
}

func (k *enclaveKey) Public() crypto.PublicKey { return k.pub }

func (k *enclaveKey) Hardware() bool { return true }

// Sign signs digest, a hash named by opts, into an ASN.1 ECDSA signature.
// rand is unused: the Enclave draws its own randomness.
func (k *enclaveKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var alg C.int
	switch opts.HashFunc() {
	case crypto.SHA1:
		alg = 1
	case crypto.SHA256:
		alg = 256
	case crypto.SHA384:
		alg = 384
	case crypto.SHA512:
		alg = 512
	default:
		return nil, fmt.Errorf("the Secure Enclave key signs SHA-1 or SHA-2 digests, not %v", opts.HashFunc())
	}
	if len(digest) != opts.HashFunc().Size() || len(digest) == 0 {
		return nil, fmt.Errorf("a %v digest is %d bytes, not %d", opts.HashFunc(), opts.HashFunc().Size(), len(digest))
	}
	var code C.long
	var desc *C.char
	sig := C.innseglSign(k.ref.ref, alg, (*C.UInt8)(unsafe.Pointer(&digest[0])), C.CFIndex(len(digest)), &code, &desc) //nolint:gocritic // cgo's generated call
	runtime.KeepAlive(k.ref)
	if sig == 0 {
		return nil, secError("signing with the Secure Enclave key", code, desc)
	}
	defer C.innseglRelease(C.CFTypeRef(sig))
	return cfBytes(sig), nil
}

func cfBytes(d C.CFDataRef) []byte {
	n := C.CFDataGetLength(d)
	if n == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(d)), C.int(n))
}

func secError(what string, code C.long, desc *C.char) error {
	msg := ""
	if desc != nil {
		msg = C.GoString(desc)
		C.free(unsafe.Pointer(desc))
	}
	if msg == "" {
		return fmt.Errorf("%s: Security framework error %d", what, int(code))
	}
	return fmt.Errorf("%s: %s (%d)", what, msg, int(code))
}
