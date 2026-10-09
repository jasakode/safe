package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	uint8_t *data;
	size_t len;
} SafeBytes;

typedef struct {
	uint8_t *signer_private_key;
	size_t signer_private_key_len;

	uint8_t *signer_public_key;
	size_t signer_public_key_len;

	uint8_t *encryptor_private_key;
	size_t encryptor_private_key_len;

	uint8_t *encryptor_public_key;
	size_t encryptor_public_key_len;
} SafeKeys;
*/
import "C"

import (
	"crypto/ed25519"
	"fmt"
	"unsafe"

	bip0039 "github.com/jasakode/bip-0039"
	"github.com/jasakode/safe/internal/encryptor"
	"github.com/jasakode/safe/internal/signer"
)

// ============================================================================
// Internal Helpers
// ============================================================================

func parseLanguage(lang string) (bip0039.Language, error) {
	switch lang {
	case "chinese_simplified":
		return bip0039.LangChineseSimplified, nil

	case "chinese_traditional":
		return bip0039.LangChineseTraditional, nil

	case "czech":
		return bip0039.LangCzech, nil

	case "english":
		return bip0039.LangEnglish, nil

	case "french":
		return bip0039.LangFrench, nil

	case "italian":
		return bip0039.LangItalian, nil

	case "japanese":
		return bip0039.LangJapanese, nil

	case "korean":
		return bip0039.LangKorean, nil

	case "portuguese":
		return bip0039.LangPortuguese, nil

	case "spanish":
		return bip0039.LangSpanish, nil

	default:
		return 0, fmt.Errorf(
			"unsupported language: %s",
			lang,
		)
	}
}

func allocBytes(data []byte) *C.uint8_t {
	if len(data) == 0 {
		return nil
	}

	ptr := C.malloc(C.size_t(len(data)))
	if ptr == nil {
		return nil
	}

	dst := unsafe.Slice(
		(*byte)(ptr),
		len(data),
	)

	copy(dst, data)

	return (*C.uint8_t)(ptr)
}

func setSafeBytes(
	out *C.SafeBytes,
	data []byte,
) bool {
	if out == nil {
		return false
	}

	out.data = nil
	out.len = 0

	if len(data) == 0 {
		return true
	}

	ptr := allocBytes(data)
	if ptr == nil {
		return false
	}

	out.data = ptr
	out.len = C.size_t(len(data))

	return true
}

func readBytes(
	ptr *C.uint8_t,
	length C.size_t,
) []byte {
	if ptr == nil || length == 0 {
		return nil
	}

	return unsafe.Slice(
		(*byte)(unsafe.Pointer(ptr)),
		int(length),
	)
}

// ============================================================================
// Memory
// ============================================================================

//export Free
func Free(ptr unsafe.Pointer) {
	if ptr == nil {
		return
	}

	C.free(ptr)
}

//export FreeBytes
func FreeBytes(out *C.SafeBytes) {
	if out == nil {
		return
	}

	if out.data != nil {
		C.free(unsafe.Pointer(out.data))
	}

	out.data = nil
	out.len = 0
}

// ============================================================================
// BIP-39
// ============================================================================

//export NewEntropy
func NewEntropy(
	bitSize C.int,
	out *C.SafeBytes,
) C.int {
	if out == nil {
		return 0
	}

	out.data = nil
	out.len = 0

	entropy, err := bip0039.NewEntropy(
		int(bitSize),
	)
	if err != nil {
		return 0
	}

	if !setSafeBytes(out, entropy) {
		return 0
	}

	return 1
}

//export NewMnemonic
func NewMnemonic(
	entropy *C.uint8_t,
	entropyLen C.size_t,
	lang *C.char,
	out *C.SafeBytes,
) C.int {
	if out == nil {
		return 0
	}

	out.data = nil
	out.len = 0

	if entropy == nil {
		return 0
	}

	if lang == nil {
		return 0
	}

	switch entropyLen {
	case 16, 20, 24, 28, 32:
	default:
		return 0
	}

	entropyBytes := readBytes(
		entropy,
		entropyLen,
	)

	language, err := parseLanguage(
		C.GoString(lang),
	)
	if err != nil {
		return 0
	}

	mnemonic, err := bip0039.NewMnemonic(
		entropyBytes,
		language,
	)
	if err != nil {
		return 0
	}

	if !setSafeBytes(
		out,
		[]byte(mnemonic),
	) {
		return 0
	}

	return 1
}

//export MnemonicToEntropy
func MnemonicToEntropy(
	mnemonic *C.char,
	lang *C.char,
	out *C.SafeBytes,
) C.int {
	if out == nil {
		return 0
	}

	out.data = nil
	out.len = 0

	if mnemonic == nil {
		return 0
	}

	if lang == nil {
		return 0
	}

	mnemonicString := C.GoString(mnemonic)

	if mnemonicString == "" {
		return 0
	}

	language, err := parseLanguage(
		C.GoString(lang),
	)
	if err != nil {
		return 0
	}

	entropy, err := bip0039.MnemonicToEntropy(
		mnemonicString,
		language,
	)
	if err != nil {
		return 0
	}

	if !setSafeBytes(out, entropy) {
		return 0
	}

	return 1
}

//export MnemonicToSeed
func MnemonicToSeed(
	mnemonic *C.char,
	passphrase *C.char,
	out *C.SafeBytes,
) C.int {
	if out == nil {
		return 0
	}

	out.data = nil
	out.len = 0

	if mnemonic == nil {
		return 0
	}

	if passphrase == nil {
		return 0
	}

	mnemonicString := C.GoString(mnemonic)
	passphraseString := C.GoString(passphrase)

	if mnemonicString == "" {
		return 0
	}

	seed := bip0039.MnemonicToSeed(
		mnemonicString,
		passphraseString,
	)

	if !setSafeBytes(out, seed) {
		return 0
	}

	return 1
}

// ============================================================================
// Keys
// ============================================================================

//export CreateKeys
func CreateKeys(
	seed *C.uint8_t,
	seedLen C.size_t,
	out *C.SafeKeys,
) C.int {
	if out == nil {
		return 0
	}

	out.signer_private_key = nil
	out.signer_private_key_len = 0
	out.signer_public_key = nil
	out.signer_public_key_len = 0
	out.encryptor_private_key = nil
	out.encryptor_private_key_len = 0
	out.encryptor_public_key = nil
	out.encryptor_public_key_len = 0

	if seed == nil {
		return 0
	}

	seedBytes := readBytes(
		seed,
		seedLen,
	)

	signerKey, err := signer.NewSigner(
		seedBytes,
	)
	if err != nil {
		return 0
	}

	encryptorKey, err := encryptor.NewEncryptor(
		seedBytes,
	)
	if err != nil {
		return 0
	}

	out.signer_private_key = allocBytes(
		signerKey.PrivateKey,
	)

	if out.signer_private_key == nil {
		FreeKeys(out)
		return 0
	}

	out.signer_private_key_len = C.size_t(
		len(signerKey.PrivateKey),
	)

	out.signer_public_key = allocBytes(
		signerKey.PublicKey,
	)

	if out.signer_public_key == nil {
		FreeKeys(out)
		return 0
	}

	out.signer_public_key_len = C.size_t(
		len(signerKey.PublicKey),
	)

	out.encryptor_private_key = allocBytes(
		encryptorKey.PrivateKey,
	)

	if out.encryptor_private_key == nil {
		FreeKeys(out)
		return 0
	}

	out.encryptor_private_key_len = C.size_t(
		len(encryptorKey.PrivateKey),
	)

	out.encryptor_public_key = allocBytes(
		encryptorKey.PublicKey,
	)

	if out.encryptor_public_key == nil {
		FreeKeys(out)
		return 0
	}

	out.encryptor_public_key_len = C.size_t(
		len(encryptorKey.PublicKey),
	)

	return 1
}

//export FreeKeys
func FreeKeys(
	keys *C.SafeKeys,
) {
	if keys == nil {
		return
	}

	if keys.signer_private_key != nil {
		C.free(
			unsafe.Pointer(keys.signer_private_key),
		)
	}

	if keys.signer_public_key != nil {
		C.free(
			unsafe.Pointer(keys.signer_public_key),
		)
	}

	if keys.encryptor_private_key != nil {
		C.free(
			unsafe.Pointer(keys.encryptor_private_key),
		)
	}

	if keys.encryptor_public_key != nil {
		C.free(
			unsafe.Pointer(keys.encryptor_public_key),
		)
	}

	keys.signer_private_key = nil
	keys.signer_private_key_len = 0

	keys.signer_public_key = nil
	keys.signer_public_key_len = 0

	keys.encryptor_private_key = nil
	keys.encryptor_private_key_len = 0

	keys.encryptor_public_key = nil
	keys.encryptor_public_key_len = 0
}

// ============================================================================
// Signer
// ============================================================================

//export GetSignerPublicKey
func GetSignerPublicKey(
	privateKey *C.uint8_t,
	privateKeyLen C.size_t,
	out *C.SafeBytes,
) C.int {
	if out == nil {
		return 0
	}

	out.data = nil
	out.len = 0

	if privateKey == nil {
		return 0
	}

	key := readBytes(
		privateKey,
		privateKeyLen,
	)

	publicKey, err := signer.GetPublicKey(
		ed25519.PrivateKey(key),
	)
	if err != nil {
		return 0
	}

	if !setSafeBytes(out, publicKey) {
		return 0
	}

	return 1
}

//export Sign
func Sign(
	privateKey *C.uint8_t,
	privateKeyLen C.size_t,
	message *C.uint8_t,
	messageLen C.size_t,
	out *C.SafeBytes,
) C.int {
	if out == nil {
		return 0
	}

	out.data = nil
	out.len = 0

	if privateKey == nil {
		return 0
	}

	if message == nil && messageLen != 0 {
		return 0
	}

	key := readBytes(
		privateKey,
		privateKeyLen,
	)

	msg := readBytes(
		message,
		messageLen,
	)

	signature := signer.Sign(
		ed25519.PrivateKey(key),
		msg,
	)

	if !setSafeBytes(out, signature) {
		return 0
	}

	return 1
}

//export Verify
func Verify(
	publicKey *C.uint8_t,
	publicKeyLen C.size_t,
	message *C.uint8_t,
	messageLen C.size_t,
	signature *C.uint8_t,
	signatureLen C.size_t,
) C.int {
	if publicKey == nil {
		return 0
	}

	if message == nil && messageLen != 0 {
		return 0
	}

	if signature == nil {
		return 0
	}

	key := readBytes(
		publicKey,
		publicKeyLen,
	)

	msg := readBytes(
		message,
		messageLen,
	)

	sig := readBytes(
		signature,
		signatureLen,
	)

	valid := signer.Verify(
		ed25519.PublicKey(key),
		msg,
		sig,
	)

	if valid {
		return 1
	}

	return 0
}

// ============================================================================
// Encryptor
// ============================================================================

//export GetEncryptorPublicKey
func GetEncryptorPublicKey(
	privateKey *C.uint8_t,
	privateKeyLen C.size_t,
	out *C.SafeBytes,
) C.int {
	if out == nil {
		return 0
	}

	out.data = nil
	out.len = 0

	if privateKey == nil {
		return 0
	}

	key := readBytes(
		privateKey,
		privateKeyLen,
	)

	publicKey, err := encryptor.GetPublicKey(
		key,
	)
	if err != nil {
		return 0
	}

	if !setSafeBytes(out, publicKey) {
		return 0
	}

	return 1
}

//export Encrypt
func Encrypt(
	recipientPublicKey *C.uint8_t,
	recipientPublicKeyLen C.size_t,
	plaintext *C.uint8_t,
	plaintextLen C.size_t,
	out *C.SafeBytes,
) C.int {
	if out == nil {
		return 0
	}

	out.data = nil
	out.len = 0

	if recipientPublicKey == nil {
		return 0
	}

	if plaintext == nil && plaintextLen != 0 {
		return 0
	}

	publicKey := readBytes(
		recipientPublicKey,
		recipientPublicKeyLen,
	)

	data := readBytes(
		plaintext,
		plaintextLen,
	)

	ciphertext, err := encryptor.Encrypt(
		publicKey,
		data,
	)
	if err != nil {
		return 0
	}

	if !setSafeBytes(out, ciphertext) {
		return 0
	}

	return 1
}

//export Decrypt
func Decrypt(
	privateKey *C.uint8_t,
	privateKeyLen C.size_t,
	ciphertext *C.uint8_t,
	ciphertextLen C.size_t,
	out *C.SafeBytes,
) C.int {
	if out == nil {
		return 0
	}

	out.data = nil
	out.len = 0

	if privateKey == nil {
		return 0
	}

	if ciphertext == nil && ciphertextLen != 0 {
		return 0
	}

	key := readBytes(
		privateKey,
		privateKeyLen,
	)

	data := readBytes(
		ciphertext,
		ciphertextLen,
	)

	plaintext, err := encryptor.Decrypt(
		key,
		data,
	)
	if err != nil {
		return 0
	}

	if !setSafeBytes(out, plaintext) {
		return 0
	}

	return 1
}

// ============================================================================
// Entry Point
// ============================================================================

func main() {}
