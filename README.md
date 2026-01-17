# Certificate Authority CBZ

A lightweight command-line utility for Linux written in C++ that functions as a simple Certificate Authority. It parses ASN.1/DER encoded files and generates Certificates and Certificate Signing Requests (CSRs).

This project was developed for a university Cryptography course to demonstrate low-level implementations of cryptographic standards without relying entirely on high-level abstraction libraries.

## System Requirements

This software has been developed for and tested exclusively on **Linux**.

### Dependencies

Requirements:
- GMP (GNU Multiple Precision Arithmetic Library)
- OpenSSL (`libcrypto`)
- GNU Make
- g++ (supporting C++23)

### Installation

**Debian / Ubuntu / Linux Mint**
```bash
sudo apt update
sudo apt install build-essential libssl-dev libgmp-dev
```

**Fedora / RHEL / CentOS**
```bash
sudo dnf install make gcc-c++ openssl-devel gmp-devel
```

**Arch Linux**
```bash
sudo pacman -S base-devel openssl gmp
```

## Build Instructions

To compile the project, clone the repository and run make.

```bash
git clone git@github.com:p-piotr/certificate-authority-cbz.git
cd certificate-authority-cbz/ca-cbz
make
```

The resulting binary will be located at: `build/out/ca-cbz`

## Usage

Generate a self-signed root certificate used to sign other requests. Requires an existing private key.

```bash
./build/out/ca-cbz gen-self-signed-cert \
    --key private/ca.key \
    --out certs/ca.crt \
    --days 3650
```

Create a CSR for a server or client key. It will prompt for Subject details  during execution.

```bash
./build/out/ca-cbz gen-csr \
    --key private/site.key \
    --out requests/site.csr
```

Acts as the CA to sign a CSR. This generates the final public certificate for the entity.

```bash
./build/out/ca-cbz gen-cert \
    --cacert certs/ca.crt \
    --cakey private/ca.key \
    --csr requests/site.csr \
    --out certs/site.crt \
    --days 365
```

### Components

**ASN.1 Parser**
A custom parser for ASN.1/DER encoded files. It maps the binary input to C++ objects. To maintain performance, ASN.1 objects share the underlying memory buffer of the raw file to avoid unnecessary memory copying.

**PKCS Structures**
Implements classes that represent standard PKCS structures, allowing manipulation of keys, signatures, and certificate fields during runtime.

**Cryptographic Primitives**
The project uses a hybrid approach to cryptography:
- RSA signing and verification are implemented manually to adhere to RFC 8017.
- SHA-256 (hashing) and AES-CBC (private key encryption) utilize OpenSSL implementations.

## Capabilities and Limitations

**Supported Algorithms**
- RSA
- SHA-256
- AES-CBC (for key protection)

**Supported Certificate Extensions**
- authorityKeyIdentifier
- subjectKeyIdentifier
- basicConstraints
- subjectAlternativeName

*Note: Keys must be generated externally (e.g., via OpenSSL CLI) before being used*

## Security Features

**Memory Sanitization**
The `security.hpp` utilities ensure that memory buffers containing sensitive information are explicitly zeroized immediately after they are no longer required by the program.

**Encrypted Key Storage**
Private keys are handled in an encrypted format using AES-CBC to prevent plain-text exposure on the disk.

## Testing and Demonstration

A full integration test is available in the `demo` directory.

```bash
cd demo
sudo ./run.sh
```

The `run.sh` script performs the following actions:
1. Generates a local Certificate Authority.
2. Adds the CA to the system trust store and Firefox (if available).
3. Signs a server certificate using the CA.
4. Starts a local Python HTTPS server.

## Lessons Learned

- Deeper understanding of ASN.1 encoding rules and DER binary formats.
- Manual implementation of RSA primitives provided insight into the mathematical foundations of PKCS#1.
- Practical experience with modern C++.


This software was written for educational purposes to demonstrate the underlying mechanics of a Public Key Infrastructure. It has not undergone a professional security audit. **Do not use this tool to secure any sensitive data.**

## Standards & RFCs

- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017): PKCS #1: RSA Cryptography Specifications Version 2.2 (PSS and OAEP schemes).
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280): Internet X.509 Public Key Infrastructure Certificate and CRL Profile.
- [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986): PKCS #10: Certification Request Syntax Specification.
- [RFC 3447](https://datatracker.ietf.org/doc/html/rfc3447): Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1
