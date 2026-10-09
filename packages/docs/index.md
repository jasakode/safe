---
layout: home

hero:
  name: Safe
  text: Cryptography for TypeScript
  tagline: Entropy, BIP-39, key derivation, encryption, and digital signatures.
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started
    - theme: alt
      text: API Reference
      link: /api

features:
  - title: BIP-39
    details: Generate entropy, create mnemonic phrases, and derive seeds.
  - title: Encryption
    details: Authenticated encryption and decryption.
  - title: Digital Signatures
    details: Sign messages and verify signatures.
---

## Download Native Libraries

Download the native shared library for your operating system and architecture.

| Platform | Architecture          | Binary                                                 | Header                                              |
| -------- | --------------------- | ------------------------------------------------------ | --------------------------------------------------- |
| macOS    | Intel (AMD64)         | [Download `.dylib`](/safe/bin/darwin/amd64/safe.dylib) | [Download `.h`](/safe/bin/darwin/amd64/safe.h)      |
| macOS    | Apple Silicon (ARM64) | [Download `.dylib`](/safe/bin/darwin/arm64/safe.dylib) | [Download `.h`](/safe/bin/darwin/arm64/safe.h)      |
| Linux    | AMD64                 | [Download `.so`](/safe/bin/linux/amd64/libbip0039.so)  | [Download `.h`](/safe/bin/linux/amd64/libbip0039.h) |
| Linux    | ARM64                 | [Download `.so`](/safe/bin/linux/arm64/libbip0039.so)  | [Download `.h`](/safe/bin/linux/arm64/libbip0039.h) |
| Windows  | AMD64                 | [Download `.dll`](/safe/bin/windows/amd64/safe.dll)    | [Download `.h`](/safe/bin/windows/amd64/safe.h)     |
| Windows  | ARM64                 | [Download `.dll`](/safe/bin/windows/arm64/safe.dll)    | [Download `.h`](/safe/bin/windows/arm64/safe.h)     |

**Note:** These libraries are native binaries. Download the version matching your operating system and CPU architecture. The C header files are provided for native integration.
