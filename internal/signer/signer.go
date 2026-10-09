package signer

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
)

const (
	// SignerSeedSize is the required size of the master seed in bytes.
	//
	// This is intentionally 64 bytes because it is designed to consume
	// a BIP-39 seed, which is 512 bits (64 bytes).
	SignerSeedSize = 64

	// PrivateKeySize is the size of an Ed25519 private key in bytes.
	PrivateKeySize = ed25519.PrivateKeySize

	// PublicKeySize is the size of an Ed25519 public key in bytes.
	PublicKeySize = ed25519.PublicKeySize

	// SignatureSize is the size of an Ed25519 signature in bytes.
	SignatureSize = ed25519.SignatureSize

	// Ed25519SeedSize is the size of the native Ed25519 seed in bytes.
	Ed25519SeedSize = ed25519.SeedSize

	// DerivationDomain is the domain-separation string used to derive
	// the Ed25519 private seed from the 64-byte Signer seed.
	//
	// This value is part of the cryptographic protocol and MUST NOT be
	// changed in a compatible implementation.
	DerivationDomain = "SAFE/Signer/Ed25519/v1"
)

type Signer struct {
	// Algorithm identifies the signature algorithm.
	//
	// Value: "Ed25519"
	Algorithm string

	// Derivation identifies how the Ed25519 key is derived from the
	// 64-byte Signer seed.
	//
	// Value: "SHA-512"
	Derivation string

	// Version identifies the key derivation protocol version.
	//
	// Value: 1
	Version uint8

	// PrivateKey is the Ed25519 private key.
	//
	// Size: 64 bytes.
	PrivateKey ed25519.PrivateKey

	// PublicKey is the Ed25519 public key.
	//
	// Size: 32 bytes.
	PublicKey ed25519.PublicKey
}

// NewSigner deterministically derives an Ed25519 key pair from a
// 64-byte Signer seed.
//
// Key derivation:
//
//	derived = SHA-512(DerivationDomain || seed)
//	privateSeed = derived[0:32]
//	privateKey = Ed25519.PrivateKeyFromSeed(privateSeed)
//	publicKey  = Ed25519.PublicKey(privateKey)
//
// The 64-byte input is expected to be a BIP-39 seed.
//
// Compatibility:
// The derivation domain, hash function, byte ordering, slice boundaries,
// and Ed25519 algorithm are part of the protocol. Implementations in
// other languages MUST reproduce these steps exactly.
func NewSigner(seed []byte) (*Signer, error) {
	if len(seed) != SignerSeedSize {
		return nil, errors.New("signer seed must be exactly 64 bytes")
	}

	// Domain-separated derivation:
	//
	// SHA-512(
	//     "SAFE/Signer/Ed25519/v1" ||
	//     seed
	// )
	//
	// The domain is encoded as its UTF-8 byte representation.
	h := sha512.New()
	_, _ = h.Write([]byte(DerivationDomain))
	_, _ = h.Write(seed)

	derived := h.Sum(nil)

	// Ed25519 requires a 32-byte private seed.
	privateSeed := derived[:Ed25519SeedSize]

	privateKey := ed25519.NewKeyFromSeed(privateSeed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &Signer{
		Algorithm:  "Ed25519",
		Derivation: "SHA-512",
		Version:    1,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// GetPublicKey derives the Ed25519 public key from a private key.
func GetPublicKey(privateKey ed25519.PrivateKey) (ed25519.PublicKey, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, errors.New(
			"private key must be exactly 64 bytes",
		)
	}

	return privateKey.Public().(ed25519.PublicKey), nil
}

// Sign creates an Ed25519 signature for message using privateKey.
//
// privateKey must be a valid 64-byte Ed25519 private key.
//
// The returned signature is always 64 bytes.
func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

// Verify verifies an Ed25519 signature against message and publicKey.
//
// publicKey must be a valid 32-byte Ed25519 public key.
//
// Returns true if the signature is valid, otherwise false.
func Verify(publicKey ed25519.PublicKey, message []byte, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}
