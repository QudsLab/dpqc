# dpqc

**DPQC**: Developer's Post-Quantum Cryptography Library

[![PyPI version](https://badge.fury.io/py/dpqc.svg)](https://pypi.org/project/dpqc/)
[![GitHub](https://img.shields.io/github/license/QudsLab/dpqc)](https://github.com/QudsLab/dpqc)

## Install

```bash
pip install dpqc
```

## Quick Start

```python
from dpqc import MLKEM512, MLDSA44

# Example: Key Encapsulation (KEM)
kem = MLKEM512()
public_key, secret_key = kem.keypair()
ciphertext, shared_secret_enc = kem.encapsulate(public_key)
shared_secret_dec = kem.decapsulate(ciphertext, secret_key)
assert shared_secret_enc == shared_secret_dec

# Example: Digital Signature
sig = MLDSA44()
public_key, secret_key = sig.keypair()
message = b"Hello PQC!"
signature = sig.sign(message, secret_key)
verified = sig.verify(signature, public_key)
assert verified == message
```

## Features
- ML-KEM (512/768/1024)
- ML-DSA (44/65/87)
- Falcon (512/1024)
- Cross-platform: Windows, Linux, macOS

## Documentation
- [GitHub Repository](https://github.com/QudsLab/dpqc)
- [PyPI Package](https://pypi.org/project/dpqc/)

## License
MIT