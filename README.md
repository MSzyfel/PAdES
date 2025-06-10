# PAdES Signature Tool

A tool for emulating a qualified electronic signature according to the PAdES standard (PDF Advanced Electronic Signature).

## Project Description

The project consists of two applications:

1. **Helper application for RSA key generation** – allows generating an RSA key pair, encrypting the private key using AES, and saving it to a USB drive.
2. **Main application for signing PDF documents** – enables signing PDF documents using the private key and verifying the signature with the public key.

## Features

### Helper application for RSA key generation:

* Generate a 4096-bit RSA key pair
* Encrypt the private key using AES-256
* Save the encrypted private key to a USB drive
* Save the public key to the hard drive

### Main application for signing PDF documents:

* Automatic detection of USB drive with the private key
* Signing PDF documents according to the PAdES standard
* Signature verification
* Graphical user interface with status/message icons

## System Requirements

* Python 3.8 or newer
* Libraries listed in the requirements.txt file
* Operating systems: Windows, macOS, Linux

## Usage Scenario

1. Launch the helper application for RSA key generation
2. Enter the PIN used to encrypt the private key
3. Select the USB drive where the encrypted private key will be saved
4. Select the location where the public key will be saved
5. Launch the main application for signing PDF documents
6. Connect the USB drive with the private key
7. Select the PDF document to sign
8. Enter the PIN to decrypt the private key
9. Sign the document
10. To verify the signature, select the signed PDF document and the public key

### Documentation Generation

To generate documentation using Doxygen:

1. Install Doxygen:

   * Windows: Download and install from the [official website](https://www.doxygen.nl/download.html)
   * macOS: `brew install doxygen`
   * Linux: `sudo apt-get install doxygen`

2. Generate the documentation:

```bash
cd docs
doxygen Doxyfile
```

## Documentation

Code documentation is available in the `docs/` directory as simple web pages. Start with `/docs/html/index.html`.
