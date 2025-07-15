
# Advanced Steganography Tool

This is a Python-based steganography tool that allows you to hide secret messages within image files using the Least Significant Bit (LSB) technique. It comes with several advanced features to enhance security and efficiency.

---

## Features

- **Least Significant Bit (LSB) Embedding**: Hides data by modifying the least significant bits of pixel color values, making changes visually imperceptible.
- **Variable Bits Per Channel**: Allows you to specify how many LSBs (1 to 8) per color channel should be used for embedding. More bits increase capacity but may increase visual distortion.
- **Password Protection (XOR Encryption with PBKDF2)**: Encrypts the message using a password-derived key (PBKDF2-HMAC-SHA256) and XOR cipher before embedding, providing an additional layer of security.
- **Message Compression (Zlib)**: Compresses the message data using zlib before embedding, significantly increasing the effective storage capacity within the image.
- **Randomized Pixel Embedding**: Instead of embedding data sequentially, pixels are chosen in a pseudo-random order. The random sequence is generated using the provided password (or a default seed if no password), making statistical analysis more challenging for an attacker.
- **Intelligent Header**: Embeds a hidden header at the beginning of the steganographic data. This header contains:
  - A Magic Number to identify files encoded by this tool.
  - The Bits Per Channel used for the main message data.
  - Flags indicating whether the message is encrypted and/or compressed.
  - Salt used for password derivation (if encrypted).
  - A CRC32 Checksum of the original message for integrity verification during decoding.
  - The header itself is always embedded using 1 LSB per channel for universal readability.
- **Robust Error Handling**: Custom exceptions and comprehensive checks for file existence, image processing issues, message capacity, and password errors.
- **Progress Indicators**: Uses `tqdm` to display real-time progress bars during encoding and decoding operations.
- **Output Format Selection**: Allows saving the encoded image in lossless formats like PNG, BMP, or TIFF.

---

## Installation

### Clone the repository:

```bash
git clone https://github.com/CRUSVEDER/Image-Steganography-Tool.git
cd steganography-tool
````

### Install dependencies:

This tool requires the `Pillow` (PIL Fork) and `tqdm` libraries. You can install them using pip:

```bash
pip install Pillow tqdm
```

### Python Version

Ensure you have **Python 3.6** or newer installed.

---

## Usage

To run the tool, execute the Python script from your terminal:

```bash
python steganography_tool.py
```

You will be presented with an interactive menu:

```
--- Welcome to the Advanced Steganography Tool! ---

Choose an option:
1. Encode a message into an image
2. Decode a message from an image
3. Exit
Enter your choice (1, 2, or 3):
```

---

### 1. Encoding a Message

Select option `1` to encode. You will be prompted for:

* Path of the original image: e.g., `my_image.png`
* Secret message to encode
* Output file name: e.g., `encoded_image.png` (PNG is recommended for lossless embedding)
* Number of bits per channel (1–8): Default is 1
* Password for encryption (optional)
* Enable compression (y/n)
* Output format (PNG, BMP, TIFF)

#### Example:

```
Enter your choice (1, 2, or 3): 1
Enter the path of the original image (e.g., image.png): input.png
Enter the secret message to encode: This is a very secret message!
Enter the desired output file name: output_encrypted_compressed.png
Enter number of bits per channel (1-8, default: 1): 2
Enter a password for encryption (leave empty for no encryption): mysecretpass123
Compress message before embedding? (y/n, default: n): y
Enter output image format (PNG, BMP, TIFF, leave empty for PNG): PNG
```

---

### 2. Decoding a Message

Select option `2` to decode. You will be prompted for:

* Path of the encoded image: e.g., `encoded_image.png`
* Password for decryption: Must match the password used during encoding. Leave empty if the message was not encrypted.

The tool will automatically detect the bits per channel, compression, and encryption flags from the hidden header.

#### Example:

```
Enter your choice (1, 2, or 3): 2
Enter the path of the encoded image: output_encrypted_compressed.png
Enter the password for decryption (leave empty if not encrypted): mysecretpass123
```

The decoded message will be printed to the console.

---

## Technical Details

* **LSB Principle**: Modifies the least significant bits of the RGB channels. For example, if `bits_per_channel = 1`, it changes only the last bit of each 8-bit color value.
* **Header Structure**: A fixed-size header is embedded using 1 LSB per channel. It includes metadata like:

  * Magic number
  * bits\_per\_channel
  * Flags for encryption/compression
  * Salt for PBKDF2
  * CRC32 checksum
* **Encryption**: Uses `hashlib.pbkdf2_hmac` to derive a strong cryptographic key from your password and a randomly generated salt. XOR cipher is used for message encryption.
* **Compression**: `zlib` compresses the message before embedding to save space.
* **Randomized Embedding**: Uses `random.shuffle` on pixel coordinates. The seed comes from the password or a default string.
* **CRC32 Checksum**: Ensures message integrity by validating the extracted message against the original CRC.

---

## Error Handling

Custom exceptions used:

* `SteganographyError`
* `MessageTooLargeError`
* `ImageProcessingError`
* `PasswordError`
* `HeaderError`

---

## Contributing

Feel free to fork the repository, open issues, or submit pull requests.

---

## License

This project is open-source and available under the **MIT License**.


