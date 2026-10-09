package encryptor

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// EncryptorSeedSize is the required size of the seed in bytes.
	//
	// The seed is expected to be a BIP-39 seed, which is 64 bytes.
	EncryptorSeedSize = 64

	// X25519PrivateKeySize is the size of an X25519 private key.
	X25519PrivateKeySize = 32

	// X25519PublicKeySize is the size of an X25519 public key.
	X25519PublicKeySize = 32

	// ChaCha20Poly1305KeySize is the size of the ChaCha20-Poly1305 key.
	ChaCha20Poly1305KeySize = chacha20poly1305.KeySize

	// ChaCha20Poly1305NonceSize is the size of the ChaCha20-Poly1305 nonce.
	ChaCha20Poly1305NonceSize = chacha20poly1305.NonceSize

	// ChaCha20Poly1305Overhead is the size of the Poly1305 authentication tag.
	ChaCha20Poly1305Overhead = chacha20poly1305.Overhead

	// DerivationDomain is the domain used to derive the X25519 private key
	// from the 64-byte Encryptor seed.
	//
	// This value is part of the cryptographic protocol and must not be
	// changed without changing the protocol version.
	DerivationDomain = "SAFE/Encryptor/X25519/v1"

	// EncryptionDomain is the HKDF information used to derive the
	// ChaCha20-Poly1305 encryption key.
	//
	// This value is part of the cryptographic protocol and must not be
	// changed without changing the protocol version.
	EncryptionDomain = "SAFE/Encryptor/ChaCha20-Poly1305/v1"
)

type Encryptor struct {
	// Algorithm identifies the key agreement algorithm.
	//
	// Value: "X25519"
	Algorithm string

	// KDF identifies the key derivation function.
	//
	// Value: "HKDF-SHA-512"
	KDF string

	// Cipher identifies the authenticated encryption algorithm.
	//
	// Value: "ChaCha20-Poly1305"
	Cipher string

	// Version identifies the encryption protocol version.
	//
	// Value: 1
	Version uint8

	// PrivateKey is the X25519 private key.
	//
	// Size: 32 bytes.
	PrivateKey []byte

	// PublicKey is the X25519 public key.
	//
	// Size: 32 bytes.
	PublicKey []byte
}

// deriveEncryptionKey derives the 32-byte ChaCha20-Poly1305 key
// from the X25519 shared secret using HKDF-SHA-512.
func deriveEncryptionKey(sharedSecret []byte) ([]byte, error) {
	hkdfReader := hkdf.New(
		sha512.New,
		sharedSecret,
		nil,
		[]byte(EncryptionDomain),
	)

	key := make([]byte, ChaCha20Poly1305KeySize)

	if _, err := hkdfReader.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

// NewEncryptor creates an Encryptor deterministically from a 64-byte seed.
//
// Key derivation:
//
//	derived = SHA-512(
//	    UTF-8(DerivationDomain) || seed
//	)
//
//	privateKey = X25519PrivateKey(derived[0:32])
//	publicKey  = X25519PublicKey(privateKey)
//
// The 64-byte seed is expected to be a BIP-39 seed.
//
// Implementations in other languages must reproduce these operations
// exactly to generate the same key pair.
func NewEncryptor(seed []byte) (*Encryptor, error) {
	if len(seed) != EncryptorSeedSize {
		return nil, errors.New("encryptor seed must be exactly 64 bytes")
	}

	h := sha512.New()

	_, _ = h.Write([]byte(DerivationDomain))
	_, _ = h.Write(seed)

	derived := h.Sum(nil)

	curve := ecdh.X25519()

	privateKey, err := curve.NewPrivateKey(
		derived[:X25519PrivateKeySize],
	)
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.PublicKey()

	return &Encryptor{
		Algorithm:  "X25519",
		KDF:        "HKDF-SHA-512",
		Cipher:     "ChaCha20-Poly1305",
		Version:    1,
		PrivateKey: privateKey.Bytes(),
		PublicKey:  publicKey.Bytes(),
	}, nil
}

// GetPublicKey derives the X25519 public key from a private key.
func GetPublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != X25519PrivateKeySize {
		return nil, errors.New(
			"private key must be exactly 32 bytes",
		)
	}

	curve := ecdh.X25519()

	key, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return key.PublicKey().Bytes(), nil
}

// Encrypt encrypts plaintext for the recipient's X25519 public key.
//
// A new ephemeral X25519 key pair is generated for every encryption.
//
// Key agreement:
//
//	sharedSecret = X25519(
//	    ephemeralPrivateKey,
//	    recipientPublicKey,
//	)
//
// Key derivation:
//
//	key = HKDF-SHA-512(
//	    IKM  = sharedSecret,
//	    salt = nil,
//	    info = EncryptionDomain,
//	    L    = 32,
//	)
//
// Encryption:
//
//	ciphertext = ChaCha20-Poly1305(
//	    key,
//	    random 12-byte nonce,
//	    plaintext,
//	    nil,
//	)
//
// Final ciphertext format:
//
//	[ ephemeralPublicKey | nonce | ciphertext ]
//
//	32 bytes            | 12 bytes | N + 16 bytes
//
// The final 16 bytes are the Poly1305 authentication tag.
func Encrypt(recipientPublicKey []byte, plaintext []byte) ([]byte, error) {
	if len(recipientPublicKey) != X25519PublicKeySize {
		return nil, errors.New(
			"recipient public key must be exactly 32 bytes",
		)
	}

	curve := ecdh.X25519()

	recipientKey, err := curve.NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, err
	}

	// Generate a fresh ephemeral key pair for every encryption.
	ephemeralPrivate, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := ephemeralPrivate.ECDH(recipientKey)
	if err != nil {
		return nil, err
	}

	key, err := deriveEncryptionKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, ChaCha20Poly1305NonceSize)

	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	encrypted := aead.Seal(
		nil,
		nonce,
		plaintext,
		nil,
	)

	ephemeralPublic := ephemeralPrivate.PublicKey().Bytes()

	result := make(
		[]byte,
		0,
		len(ephemeralPublic)+len(nonce)+len(encrypted),
	)

	result = append(result, ephemeralPublic...)
	result = append(result, nonce...)
	result = append(result, encrypted...)

	return result, nil
}

// Decrypt decrypts ciphertext using the recipient's X25519 private key.
//
// Expected ciphertext format:
//
//	[ ephemeralPublicKey | nonce | ciphertext ]
//
//	32 bytes            | 12 bytes | N + 16 bytes
func Decrypt(privateKey []byte, ciphertext []byte) ([]byte, error) {
	if len(privateKey) != X25519PrivateKeySize {
		return nil, errors.New(
			"private key must be exactly 32 bytes",
		)
	}

	minCiphertextSize :=
		X25519PublicKeySize +
			ChaCha20Poly1305NonceSize +
			ChaCha20Poly1305Overhead

	if len(ciphertext) < minCiphertextSize {
		return nil, errors.New("invalid ciphertext")
	}

	curve := ecdh.X25519()

	recipientKey, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	ephemeralPublic, err := curve.NewPublicKey(
		ciphertext[:X25519PublicKeySize],
	)
	if err != nil {
		return nil, err
	}

	nonceStart := X25519PublicKeySize
	nonceEnd := nonceStart + ChaCha20Poly1305NonceSize

	nonce := ciphertext[nonceStart:nonceEnd]
	encrypted := ciphertext[nonceEnd:]

	sharedSecret, err := recipientKey.ECDH(ephemeralPublic)
	if err != nil {
		return nil, err
	}

	key, err := deriveEncryptionKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(
		nil,
		nonce,
		encrypted,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
