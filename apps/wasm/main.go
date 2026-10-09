//go:build js && wasm

// Package main provides the WebAssembly entrypoint for the BIP-0039 library.
package main

import (
	"crypto/ed25519"
	"fmt"
	"syscall/js"

	bip0039 "github.com/jasakode/bip-0039"
	"github.com/jasakode/safe/internal/encryptor"
	"github.com/jasakode/safe/internal/response"
	"github.com/jasakode/safe/internal/signer"
)

// =================================================================
// Start Code...
// =================================================================

func parseLanguage(value js.Value) (bip0039.Language, error) {
	switch value.String() {
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
		return 0, fmt.Errorf("unsupported language: %s", value.String())
	}
}

func bytesToJS(data []byte) js.Value {
	value := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(value, data)

	return value
}

func NewEntropy(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return response.ToJSFailure("bitSize is required. It must be an integer with one of these values: 128, 160, 192, 224, or 256")
	}

	bitSize := args[0].Int()

	entropy, err := bip0039.NewEntropy(bitSize)
	if err != nil {
		return response.ToJSFailure(err.Error())
	}

	result := js.Global().Get("Uint8Array").New(len(entropy))
	js.CopyBytesToJS(result, entropy)

	return response.ToJSSuccess(fmt.Sprintf("Entropy generated successfully with a size of %d bits.", bitSize), result)
}

func NewMnemonic(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return response.ToJSFailure(
			"entropy and lang are required",
		)
	}

	// Argument 0: entropy
	entropyValue := args[0]

	if entropyValue.IsUndefined() || entropyValue.IsNull() {
		return response.ToJSFailure(
			"entropy is required and must be a Uint8Array",
		)
	}

	if !entropyValue.InstanceOf(js.Global().Get("Uint8Array")) {
		return response.ToJSFailure(
			"entropy must be a Uint8Array",
		)
	}

	entropyLength := entropyValue.Get("length").Int()

	switch entropyLength {
	case 16, 20, 24, 28, 32:
		// Valid BIP-39 entropy size.
	default:
		return response.ToJSFailure(
			"entropy must contain 16, 20, 24, 28, or 32 bytes",
		)
	}

	entropy := make([]byte, entropyLength)
	js.CopyBytesToGo(entropy, entropyValue)

	// Argument 1: language
	langValue := args[1]

	if langValue.IsUndefined() || langValue.IsNull() {
		return response.ToJSFailure(
			"lang is required and must be a string",
		)
	}

	if langValue.Type() != js.TypeString {
		return response.ToJSFailure(
			"lang must be a string",
		)
	}

	lang, err := parseLanguage(langValue)
	if err != nil {
		return response.ToJSFailure(err.Error())
	}

	mnemonic, err := bip0039.NewMnemonic(entropy, lang)
	if err != nil {
		return response.ToJSFailure(
			fmt.Sprintf("failed to generate mnemonic: %s", err),
		)
	}

	return response.ToJSSuccess(
		"Mnemonic generated successfully",
		mnemonic,
	)
}

func MnemonicToEntropy(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return response.ToJSFailure(
			"mnemonic and lang are required",
		)
	}

	// Argument 0: mnemonic
	mnemonicValue := args[0]

	if mnemonicValue.IsUndefined() || mnemonicValue.IsNull() {
		return response.ToJSFailure(
			"mnemonic is required and must be a string",
		)
	}

	if mnemonicValue.Type() != js.TypeString {
		return response.ToJSFailure(
			"mnemonic must be a string",
		)
	}

	mnemonic := mnemonicValue.String()

	if mnemonic == "" {
		return response.ToJSFailure(
			"mnemonic cannot be empty",
		)
	}

	// Argument 1: language
	langValue := args[1]

	if langValue.IsUndefined() || langValue.IsNull() {
		return response.ToJSFailure(
			"lang is required and must be a string",
		)
	}

	if langValue.Type() != js.TypeString {
		return response.ToJSFailure(
			"lang must be a string",
		)
	}

	lang, err := parseLanguage(langValue)
	if err != nil {
		return response.ToJSFailure(err.Error())
	}

	entropy, err := bip0039.MnemonicToEntropy(mnemonic, lang)
	if err != nil {
		return response.ToJSFailure(
			fmt.Sprintf("failed to convert mnemonic to entropy: %s", err),
		)
	}

	data := js.Global().Get("Uint8Array").New(len(entropy))
	js.CopyBytesToJS(data, entropy)

	return response.ToJSSuccess(
		"Mnemonic converted to entropy successfully",
		data,
	)
}

func MnemonicToSeed(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return response.ToJSFailure(
			"mnemonic and passphrase are required",
		)
	}

	// Argument 0: mnemonic
	mnemonicValue := args[0]

	if mnemonicValue.IsUndefined() || mnemonicValue.IsNull() {
		return response.ToJSFailure(
			"mnemonic is required and must be a string",
		)
	}

	if mnemonicValue.Type() != js.TypeString {
		return response.ToJSFailure(
			"mnemonic must be a string",
		)
	}

	mnemonic := mnemonicValue.String()

	if mnemonic == "" {
		return response.ToJSFailure(
			"mnemonic cannot be empty",
		)
	}

	// Argument 1: passphrase
	passphraseValue := args[1]

	if passphraseValue.IsUndefined() || passphraseValue.IsNull() {
		return response.ToJSFailure(
			"passphrase is required and must be a string",
		)
	}

	if passphraseValue.Type() != js.TypeString {
		return response.ToJSFailure(
			"passphrase must be a string",
		)
	}

	passphrase := passphraseValue.String()

	seed := bip0039.MnemonicToSeed(mnemonic, passphrase)

	data := js.Global().Get("Uint8Array").New(len(seed))
	js.CopyBytesToJS(data, seed)

	return response.ToJSSuccess(
		"Mnemonic converted to seed successfully",
		data,
	)
}

func CreateKeys(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return response.ToJSFailure("seed is required")
	}

	seed := make([]byte, args[0].Length())
	js.CopyBytesToGo(seed, args[0])

	signerKey, err := signer.NewSigner(seed)
	if err != nil {
		return response.ToJSFailure(err.Error())
	}

	encryptorKey, err := encryptor.NewEncryptor(seed)
	if err != nil {
		return response.ToJSFailure(err.Error())
	}

	data := map[string]any{
		"signer_private_key":    bytesToJS(signerKey.PrivateKey),
		"signer_public_key":     bytesToJS(signerKey.PublicKey),
		"encryptor_private_key": bytesToJS(encryptorKey.PrivateKey),
		"encryptor_public_key":  bytesToJS(encryptorKey.PublicKey),
	}

	return response.ToJSSuccess(
		"Keys created successfully",
		data,
	)
}

func GetSignerPublicKey(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return response.ToJSFailure("private key is required")
	}

	privateKey := make([]byte, args[0].Length())
	js.CopyBytesToGo(privateKey, args[0])

	publicKey, err := signer.GetPublicKey(
		ed25519.PrivateKey(privateKey),
	)
	if err != nil {
		return response.ToJSFailure(err.Error())
	}

	return response.ToJSSuccess(
		"Public key derived successfully",
		bytesToJS(publicKey),
	)
}

func GetEncryptorPublicKey(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return response.ToJSFailure("private key is required")
	}

	privateKey := make([]byte, args[0].Length())
	js.CopyBytesToGo(privateKey, args[0])

	publicKey, err := encryptor.GetPublicKey(privateKey)
	if err != nil {
		return response.ToJSFailure(err.Error())
	}

	return response.ToJSSuccess(
		"Public key derived successfully",
		bytesToJS(publicKey),
	)
}

func Sign(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return response.ToJSFailure(
			"private key and message are required",
		)
	}

	privateKey := make([]byte, args[0].Length())
	js.CopyBytesToGo(privateKey, args[0])

	message := make([]byte, args[1].Length())
	js.CopyBytesToGo(message, args[1])

	signature := signer.Sign(
		ed25519.PrivateKey(privateKey),
		message,
	)

	return response.ToJSSuccess(
		"Message signed successfully",
		bytesToJS(signature),
	)
}

func Verify(this js.Value, args []js.Value) any {
	if len(args) < 3 {
		return response.ToJSFailure(
			"public key, message, and signature are required",
		)
	}

	publicKey := make([]byte, args[0].Length())
	js.CopyBytesToGo(publicKey, args[0])

	message := make([]byte, args[1].Length())
	js.CopyBytesToGo(message, args[1])

	signature := make([]byte, args[2].Length())
	js.CopyBytesToGo(signature, args[2])

	valid := signer.Verify(
		ed25519.PublicKey(publicKey),
		message,
		signature,
	)

	return response.ToJSSuccess(
		"Signature verified successfully",
		valid,
	)
}

func Encrypt(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return response.ToJSFailure(
			"recipient public key and plaintext are required",
		)
	}

	recipientPublicKey := make([]byte, args[0].Length())
	js.CopyBytesToGo(recipientPublicKey, args[0])

	plaintext := make([]byte, args[1].Length())
	js.CopyBytesToGo(plaintext, args[1])

	ciphertext, err := encryptor.Encrypt(
		recipientPublicKey,
		plaintext,
	)
	if err != nil {
		return response.ToJSFailure(err.Error())
	}

	return response.ToJSSuccess(
		"Data encrypted successfully",
		bytesToJS(ciphertext),
	)
}

func Decrypt(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return response.ToJSFailure(
			"private key and ciphertext are required",
		)
	}

	privateKey := make([]byte, args[0].Length())
	js.CopyBytesToGo(privateKey, args[0])

	ciphertext := make([]byte, args[1].Length())
	js.CopyBytesToGo(ciphertext, args[1])

	plaintext, err := encryptor.Decrypt(
		privateKey,
		ciphertext,
	)
	if err != nil {
		return response.ToJSFailure(err.Error())
	}

	return response.ToJSSuccess(
		"Data decrypted successfully",
		bytesToJS(plaintext),
	)
}

func main() {
	newEntropy := js.FuncOf(NewEntropy)
	newMnemonic := js.FuncOf(NewMnemonic)
	mnemonicToEntropy := js.FuncOf(MnemonicToEntropy)
	mnemonicToSeed := js.FuncOf(MnemonicToSeed)

	createKeys := js.FuncOf(CreateKeys)
	getSignerPublicKey := js.FuncOf(GetSignerPublicKey)
	getEncryptorPublicKey := js.FuncOf(GetEncryptorPublicKey)
	sign := js.FuncOf(Sign)
	verify := js.FuncOf(Verify)
	encrypt := js.FuncOf(Encrypt)
	decrypt := js.FuncOf(Decrypt)

	// Ini membuat objek kosong baru: {}
	obj := js.Global().Get("Object").New()

	obj.Set("newEntropy", newEntropy)
	obj.Set("newMnemonic", newMnemonic)
	obj.Set("mnemonicToEntropy", mnemonicToEntropy)
	obj.Set("mnemonicToSeed", mnemonicToSeed)
	obj.Set("createKeys", createKeys)
	obj.Set("getSignerPublicKey", getSignerPublicKey)
	obj.Set("getEncryptorPublicKey", getEncryptorPublicKey)
	obj.Set("sign", sign)
	obj.Set("verify", verify)
	obj.Set("encrypt", encrypt)
	obj.Set("decrypt", decrypt)

	js.Global().Set("__SAFE", obj)

	// Menunggu selamanya agar program tidak mati
	select {}
}
