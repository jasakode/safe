import "../bin/wasm_exec.js"
import { readFile } from "node:fs/promises";


export type Language =
    | "chinese_simplified"
    | "chinese_traditional"
    | "czech"
    | "english"
    | "french"
    | "italian"
    | "japanese"
    | "korean"
    | "portuguese"
    | "spanish";

export interface Keys {
    signer_private_key: Uint8Array;
    signer_public_key: Uint8Array;
    encryptor_private_key: Uint8Array;
    encryptor_public_key: Uint8Array;
}

export interface Response<T> {
    success: boolean;
    message: string;
    data: T;
};

export interface SafeAPI {
    newEntropy: (bitSize: number) => Response<Uint8Array>;
    newMnemonic: (entropy: Uint8Array, lang: Language) => Response<string>;
    mnemonicToEntropy: (mnemonic: string, lang: Language) => Response<Uint8Array>;
    mnemonicToSeed: (mnemonic: string, passphrase: string) => Response<Uint8Array>;
    createKeys: (seed: Uint8Array) => Response<Keys>;
    getSignerPublicKey: (privateKey: Uint8Array) => Response<Uint8Array>;
	getEncryptorPublicKey: (privateKey: Uint8Array) => Response<Uint8Array>;
    sign: (privateKey: Uint8Array, message: Uint8Array) => Response<Uint8Array>;
    verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => Response<boolean>;
    encrypt: (recipientPublicKey: Uint8Array, plaintext: Uint8Array) => Response<Uint8Array>;
    decrypt: (privateKey: Uint8Array, ciphertext: Uint8Array) => Response<Uint8Array>;
};


export async function loadSafeWasm(path: string): Promise<SafeAPI> {
    const go = new Go();

    const bytes = await readFile(path);

    const { instance } = await WebAssembly.instantiate(
        bytes,
        go.importObject,
    );

    // Go program harus tetap hidup karena API diekspos
    // melalui globalThis.__SAFE.
    void go.run(instance);

    // Beri kesempatan runtime Go menjalankan main()
    // dan menginisialisasi __SAFE.
    await new Promise<void>((resolve) => {
        queueMicrotask(resolve);
    });

    const safe = globalThis.__SAFE;

    if (!safe) {
        throw new Error(
            "Go WASM initialized but globalThis.__SAFE was not created",
        );
    }

    return safe;
};

export async function loadSafeWasmBrowser(url: string | URL): Promise<SafeAPI> {
    const go = new Go();

    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(
            `Failed to load SAFE WASM: ${response.status} ${response.statusText}`,
        );
    }

    const bytes = await response.arrayBuffer();

    const { instance } = await WebAssembly.instantiate(
        bytes,
        go.importObject,
    );

    // Go runtime harus tetap hidup karena API diekspos
    // melalui globalThis.__SAFE.
    void go.run(instance);

    // Beri kesempatan main() menjalankan inisialisasi
    // dan membuat globalThis.__SAFE.
    await new Promise<void>((resolve) => {
        queueMicrotask(resolve);
    });

    const safe = globalThis.__SAFE;

    if (!safe) {
        throw new Error(
            "Go WASM initialized but globalThis.__SAFE was not created",
        );
    }

    return safe;
};
