import { describe, expect, it, beforeAll } from "vitest";
import { loadSafeWasm, SafeAPI } from "../dist/index";




const PATH_WASM = new URL(
    "../bin/safe.wasm",
    import.meta.url,
).pathname;

interface Response<T> {
    success: boolean;
    message: string;
    data: T;
}

interface Keys {
    signer_private_key: Uint8Array;
    signer_public_key: Uint8Array;
    encryptor_private_key: Uint8Array;
    encryptor_public_key: Uint8Array;
}

let wasm: SafeAPI;

function expectSuccess<T>(response: Response<T>): T {
    expect(response.success).toBe(true);
    return response.data;
}

function expectBytesEqual(
    actual: Uint8Array,
    expected: Uint8Array,
) {
    expect(Array.from(actual)).toEqual(
        Array.from(expected),
    );
}

beforeAll(async () => {
    wasm = await loadSafeWasm(PATH_WASM);
});

describe("BIP-39", () => {
    it("should generate 256-bit entropy", () => {
        const response = wasm.newEntropy(256);

        expect(response.success).toBe(true);
        expect(response.data).toBeInstanceOf(Uint8Array);
        expect(response.data.length).toBe(32);
    });

    it("should generate mnemonic from entropy", () => {
        const entropy = expectSuccess(
            wasm.newEntropy(256),
        );

        const mnemonic = expectSuccess(
            wasm.newMnemonic(
                entropy,
                "english",
            ),
        );

        expect(typeof mnemonic).toBe("string");
        expect(mnemonic.split(" ").length).toBe(24);
    });

    it("should convert mnemonic back to entropy", () => {
        const entropy = expectSuccess(
            wasm.newEntropy(256),
        );

        const mnemonic = expectSuccess(
            wasm.newMnemonic(
                entropy,
                "english",
            ),
        );

        const restoredEntropy = expectSuccess(
            wasm.mnemonicToEntropy(
                mnemonic,
                "english",
            ),
        );

        expectBytesEqual(
            restoredEntropy,
            entropy,
        );
    });

    it("should derive a 64-byte seed", () => {
        const entropy = expectSuccess(
            wasm.newEntropy(256),
        );

        const mnemonic = expectSuccess(
            wasm.newMnemonic(
                entropy,
                "english",
            ),
        );

        const seed = expectSuccess(
            wasm.mnemonicToSeed(
                mnemonic,
                "",
            ),
        );

        expect(seed).toBeInstanceOf(Uint8Array);
        expect(seed.length).toBe(64);
    });
});

describe("Keys", () => {
    let seed: Uint8Array;
    let keys: Keys;

    beforeAll(() => {
        const entropy = expectSuccess(
            wasm.newEntropy(256),
        );

        const mnemonic = expectSuccess(
            wasm.newMnemonic(
                entropy,
                "english",
            ),
        );

        seed = expectSuccess(
            wasm.mnemonicToSeed(
                mnemonic,
                "",
            ),
        );

        keys = expectSuccess(
            wasm.createKeys(seed),
        );
    });

    it("should create all keys", () => {
        expect(keys.signer_private_key)
            .toBeInstanceOf(Uint8Array);

        expect(keys.signer_public_key)
            .toBeInstanceOf(Uint8Array);

        expect(keys.encryptor_private_key)
            .toBeInstanceOf(Uint8Array);

        expect(keys.encryptor_public_key)
            .toBeInstanceOf(Uint8Array);
    });

    it("should create keys with correct sizes", () => {
        expect(keys.signer_private_key.length)
            .toBe(64);

        expect(keys.signer_public_key.length)
            .toBe(32);

        expect(keys.encryptor_private_key.length)
            .toBe(32);

        expect(keys.encryptor_public_key.length)
            .toBe(32);
    });

    it("should derive signer public key from private key", () => {
        const publicKey = expectSuccess(
            wasm.getSignerPublicKey(
                keys.signer_private_key,
            ),
        );

        expectBytesEqual(
            publicKey,
            keys.signer_public_key,
        );
    });

    it("should derive encryptor public key from private key", () => {
        const publicKey = expectSuccess(
            wasm.getEncryptorPublicKey(
                keys.encryptor_private_key,
            ),
        );

        expectBytesEqual(
            publicKey,
            keys.encryptor_public_key,
        );
    });

    it("should deterministically create the same keys", () => {
        const keys2 = expectSuccess(
            wasm.createKeys(seed),
        );

        expectBytesEqual(
            keys2.signer_private_key,
            keys.signer_private_key,
        );

        expectBytesEqual(
            keys2.signer_public_key,
            keys.signer_public_key,
        );

        expectBytesEqual(
            keys2.encryptor_private_key,
            keys.encryptor_private_key,
        );

        expectBytesEqual(
            keys2.encryptor_public_key,
            keys.encryptor_public_key,
        );
    });
});

describe("Signer", () => {
    let keys: Keys;

    beforeAll(() => {
        const seed = expectSuccess(
            wasm.mnemonicToSeed(
                expectSuccess(
                    wasm.newMnemonic(
                        expectSuccess(
                            wasm.newEntropy(256),
                        ),
                        "english",
                    ),
                ),
                "",
            ),
        );

        keys = expectSuccess(
            wasm.createKeys(seed),
        );
    });

    it("should sign and verify a message", () => {
        const message = new TextEncoder().encode(
            "Hello SAFE",
        );

        const signature = expectSuccess(
            wasm.sign(
                keys.signer_private_key,
                message,
            ),
        );

        expect(signature.length).toBe(64);

        const valid = expectSuccess(
            wasm.verify(
                keys.signer_public_key,
                message,
                signature,
            ),
        );

        expect(valid).toBe(true);
    });

    it("should reject modified message", () => {
        const message = new TextEncoder().encode(
            "Hello SAFE",
        );

        const modifiedMessage = new TextEncoder().encode(
            "Hello SAFE!",
        );

        const signature = expectSuccess(
            wasm.sign(
                keys.signer_private_key,
                message,
            ),
        );

        const valid = expectSuccess(
            wasm.verify(
                keys.signer_public_key,
                modifiedMessage,
                signature,
            ),
        );

        expect(valid).toBe(false);
    });

    it("should reject modified signature", () => {
        const message = new TextEncoder().encode(
            "Hello SAFE",
        );

        const signature = expectSuccess(
            wasm.sign(
                keys.signer_private_key,
                message,
            ),
        );

        signature[0] ^= 0xff;

        const valid = expectSuccess(
            wasm.verify(
                keys.signer_public_key,
                message,
                signature,
            ),
        );

        expect(valid).toBe(false);
    });
});

describe("Encryptor", () => {
    let keys: Keys;

    beforeAll(() => {
        const seed = expectSuccess(
            wasm.mnemonicToSeed(
                expectSuccess(
                    wasm.newMnemonic(
                        expectSuccess(
                            wasm.newEntropy(256),
                        ),
                        "english",
                    ),
                ),
                "",
            ),
        );

        keys = expectSuccess(
            wasm.createKeys(seed),
        );
    });

    it("should encrypt and decrypt", () => {
        const plaintext = new TextEncoder().encode(
            "Hello SAFE encryption",
        );

        const ciphertext = expectSuccess(
            wasm.encrypt(
                keys.encryptor_public_key,
                plaintext,
            ),
        );

        expect(ciphertext).toBeInstanceOf(Uint8Array);
        expect(ciphertext.length).toBeGreaterThan(
            plaintext.length,
        );

        const decrypted = expectSuccess(
            wasm.decrypt(
                keys.encryptor_private_key,
                ciphertext,
            ),
        );

        expectBytesEqual(
            decrypted,
            plaintext,
        );
    });

    it("should produce different ciphertext each time", () => {
        const plaintext = new TextEncoder().encode(
            "Hello SAFE",
        );

        const ciphertext1 = expectSuccess(
            wasm.encrypt(
                keys.encryptor_public_key,
                plaintext,
            ),
        );

        const ciphertext2 = expectSuccess(
            wasm.encrypt(
                keys.encryptor_public_key,
                plaintext,
            ),
        );

        expect(
            Array.from(ciphertext1),
        ).not.toEqual(
            Array.from(ciphertext2),
        );
    });

    it("should reject modified ciphertext", () => {
        const plaintext = new TextEncoder().encode(
            "Hello SAFE",
        );

        const ciphertext = expectSuccess(
            wasm.encrypt(
                keys.encryptor_public_key,
                plaintext,
            ),
        );

        ciphertext[ciphertext.length - 1] ^= 0xff;

        const response = wasm.decrypt(
            keys.encryptor_private_key,
            ciphertext,
        );

        expect(response.success).toBe(false);
    });

    it("should not decrypt with another private key", () => {
        const plaintext = new TextEncoder().encode(
            "Secret message",
        );

        const ciphertext = expectSuccess(
            wasm.encrypt(
                keys.encryptor_public_key,
                plaintext,
            ),
        );

        const otherSeed = expectSuccess(
            wasm.mnemonicToSeed(
                expectSuccess(
                    wasm.newMnemonic(
                        expectSuccess(
                            wasm.newEntropy(256),
                        ),
                        "english",
                    ),
                ),
                "",
            ),
        );

        const otherKeys = expectSuccess(
            wasm.createKeys(otherSeed),
        );

        const response = wasm.decrypt(
            otherKeys.encryptor_private_key,
            ciphertext,
        );

        expect(response.success).toBe(false);
    });
});