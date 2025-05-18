# medcrypt : Hybrid Cryptographic-Steganographic Framework for Secure Medical Data Transmission Healthcare Systems

## Overview

MedCrypt is a hybrid cryptography and steganography system designed specifically for secure medical data transmission. The framework leverages both classic (AES+RSA) and lightweight (ChaCha20+ECC) cryptographic techniques combined with DWT-based steganography to provide multi-layered security for sensitive healthcare information.

## Features

- **Dual Cryptographic Modes**:

  - **Classic Mode**:

    - AES-128 for fast symmetric encryption
    - RSA-2048 for secure key exchange

  - **Lightweight Mode**:
    - ChaCha20 for efficient symmetric encryption
    - ECC (SECP256K1) for compact key exchange

- **DWT-based Image Steganography**:

  - Hides encrypted data within medical images using discrete wavelet transform
  - Maintains visual quality of cover images
  - Resistant to basic steganalysis

- **Command Line Interface**:
  - Easy-to-use commands for encryption, decryption, and key generation
  - Support for various image formats
  - Built-in performance evaluation tools

## Requirements

- Python 3.6+
- NumPy
- PyWavelets (pywt)
- OpenCV (cv2)
- cryptography
- Pillow

## Installation

1. Clone the repository:

```bash
git clone https://github.com/SahooBishwajeet/medcrypt.git
cd medcrypt
```

2. Create a virtual environment (optional but recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

3. Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

### Key Generation

Generate key pairs for both cryptographic modes:

```bash
# Generate RSA keys (classic mode)
python main.py genkeys -o keys -s 2048 -c classic

# Generate ECC keys (lightweight mode)
python main.py genkeys -o keys_light -s 256 -c lightweight
```

### Encrypt & Hide Data

Encrypt a file and hide it within a cover image using either mode:

```bash
# Classic mode (RSA+AES)
python main.py encrypt -m message.txt -i cover.png -o stego_classic.png -k keys/public_key.pem -c classic

# Lightweight mode (ECC+ChaCha20)
python main.py encrypt -m message.txt -i cover.png -o stego_light.png -k keys_light/public_key.pem -c lightweight
```

Parameters:

- `-m, --message`: Path to the message file to encrypt
- `-i, --image`: Path to the cover image
- `-o, --output`: Path for the output stego image
- `-k, --key`: Path to the public key file
- `-c, --crypto`: Cryptography mode (`classic` or `lightweight`)
- `-a, --alpha`: Embedding strength (default: 0.1, range: 0.05-0.2)

### Extract & Decrypt Data

Extract and decrypt hidden data from a stego image:

```bash
# Classic mode
python main.py decrypt -i stego_classic.png -o recovered.txt -k keys/private_key.pem

# Lightweight mode
python main.py decrypt -i stego_light.png -o recovered.txt -k keys_light/private_key.pem
```

Parameters:

- `-i, --image`: Path to the stego image
- `-o, --output`: Path for the decrypted output
- `-k, --key`: Path to the private key file
- `-a, --alpha`: Embedding strength used during encryption

### Performance Evaluation

Run comprehensive performance analysis:

```bash
# Full evaluation of both cryptographic modes
python test/evaluations.py

# Generate histogram analysis
python test/histogram.py --image1 cover.png --image2 stego.png --title1 "Original" --title2 "Stego" --output histogram.png --metrics
```

## Best Practices

- Use PNG format for stego images to avoid lossy compression
- Keep the alpha value balanced (0.1-0.2) for optimal image quality
- Choose crypto mode based on your needs:
  - Classic mode for maximum security
  - Lightweight mode for better performance
- Ensure the cover image has sufficient capacity for your message
- Keep private keys secure and never share them
