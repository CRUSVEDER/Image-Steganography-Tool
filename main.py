from PIL import Image
import os
import random
import zlib
import hashlib
import struct
from tqdm import tqdm
import binascii

class SteganographyError(Exception):
    pass

class MessageTooLargeError(SteganographyError):
    pass

class ImageProcessingError(SteganographyError):
    pass

class PasswordError(SteganographyError):
    pass

class HeaderError(SteganographyError):
    pass

NULL_CHAR = '\0'
MAGIC_NUMBER = b'\xCA\xFE\xBA\xBE'
SALT_LENGTH = 16

def derive_key(password, salt, iterations=100000, key_length=32):
    if not password:
        raise PasswordError("Password cannot be empty.")
    if not salt or len(salt) != SALT_LENGTH:
        raise PasswordError(f"Invalid or missing salt. Expected {SALT_LENGTH} bytes.")

    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen=key_length
    )

def xor_encrypt_decrypt(data_bytes, key_bytes):
    if not key_bytes:
        raise PasswordError("Encryption key cannot be empty.")
    
    key_len = len(key_bytes)
    return bytes(data_bytes[i] ^ key_bytes[i % key_len] for i in range(len(data_bytes)))

def compress_data(data_bytes):
    return zlib.compress(data_bytes, level=9)

def decompress_data(data_bytes):
    try:
        return zlib.decompress(data_bytes)
    except zlib.error as e:
        raise ImageProcessingError(f"Decompression failed: {e}. Data might be corrupted or not compressed.")

def calculate_crc32(data_bytes):
    return binascii.crc32(data_bytes) & 0xFFFFFFFF

def encode_message(img_path, message, output_path, bits_per_channel=1, password=None, compress=False, output_format=None):
    if not 1 <= bits_per_channel <= 8:
        raise ValueError("Bits per channel must be between 1 and 8.")
    
    if output_format:
        output_format = output_format.upper()
        if output_format not in ['PNG', 'BMP', 'TIFF']:
            print(f"Warning: '{output_format}' is not a recommended lossless format. Using PNG.")
            output_format = 'PNG'
    else:
        output_format = os.path.splitext(output_path)[1][1:].upper() or 'PNG'
        if output_format not in ['PNG', 'BMP', 'TIFF']:
            print(f"Warning: Original format '{output_format}' is not lossless. Saving as PNG.")
            output_format = 'PNG'

    if os.path.exists(output_path):
        overwrite = input(f"Output file '{output_path}' already exists. Overwrite? (y/n): ").strip().lower()
        if overwrite != 'y':
            print("Operation cancelled by user.")
            return

    try:
        img = Image.open(img_path)
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        elif img.mode == 'RGBA':
            print("Warning: Image has an alpha channel. Converting to RGB for embedding.")
            img = img.convert('RGB')

    except FileNotFoundError:
        raise FileNotFoundError(f"Error: Image not found at '{img_path}'. Please check the path.")
    except Exception as e:
        raise ImageProcessingError(f"Error opening or processing image '{img_path}': {e}")

    encoded_img = img.copy()
    width, height = img.size

    original_message_bytes = message.encode('utf-8')
    checksum = calculate_crc32(original_message_bytes)

    flags = 0
    salt = b''
    key_for_xor = b''

    if password:
        flags |= 0b00000001
        salt = os.urandom(SALT_LENGTH)
        try:
            key_for_xor = derive_key(password, salt)
            message_bytes = xor_encrypt_decrypt(original_message_bytes, key_for_xor)
            print("Message encrypted.")
        except PasswordError as e:
            raise PasswordError(f"Encryption failed: {e}")
        except Exception as e:
            raise PasswordError(f"An unexpected error occurred during encryption: {e}")
    else:
        message_bytes = original_message_bytes

    if compress:
        flags |= 0b00000010
        message_bytes = compress_data(message_bytes)
        print("Message compressed.")

    final_message_bytes = message_bytes + NULL_CHAR.encode('utf-8')

    header_bytes = MAGIC_NUMBER
    header_bytes += struct.pack('B', bits_per_channel)
    header_bytes += struct.pack('B', flags)
    header_bytes += struct.pack('B', len(salt))
    if salt:
        header_bytes += salt
    header_bytes += struct.pack('>I', checksum)

    header_binary = ''.join(format(byte, '08b') for byte in header_bytes)
    
    data_to_embed_binary = ''.join(format(byte, '08b') for byte in final_message_bytes)

    total_bits_for_header = len(header_binary)
    total_bits_for_message = len(data_to_embed_binary)
    total_bits_to_embed = total_bits_for_header + total_bits_for_message

    max_capacity_bits = width * height * 3 * bits_per_channel

    if total_bits_to_embed > max_capacity_bits:
        raise MessageTooLargeError(
            f"Message (including header) is too large to encode in the image. "
            f"Required bits: {total_bits_to_embed}, Available bits: {max_capacity_bits}. "
            f"Consider a larger image, more bits per channel, or shorter message."
        )

    pixel_coords = [(x, y) for y in range(height) for x in range(width)]
    
    seed_data = password.encode('utf-8') if password else b'default_stego_seed'
    seed_hash = hashlib.sha256(seed_data).digest()
    random.seed(int.from_bytes(seed_hash[:8], 'big'))
    random.shuffle(pixel_coords)

    data_index = 0
    print(f"Embedding {total_bits_to_embed} bits into {output_path}...")
    with tqdm(total=total_bits_to_embed, desc="Encoding progress", unit="bit") as pbar:
        for x, y in pixel_coords:
            if data_index >= total_bits_to_embed:
                break

            pixel = list(img.getpixel((x, y)))
            for i in range(3):
                if data_index < total_bits_to_embed:
                    # Determine if we are embedding header or message data
                    if data_index < total_bits_for_header:
                        bits_to_embed_current = header_binary[data_index : data_index + 1] # Header always 1 BPC
                        bpc_used = 1
                    else:
                        # Adjust index for message data
                        message_data_idx = data_index - total_bits_for_header
                        bits_to_embed_current = data_to_embed_binary[message_data_idx : message_data_idx + bits_per_channel]
                        bpc_used = bits_per_channel
                    
                    mask = ~((1 << bpc_used) - 1)
                    
                    pixel[i] = (pixel[i] & mask) | int(bits_to_embed_current, 2)
                    
                    data_index += bpc_used
                    pbar.update(bpc_used)
            
            encoded_img.putpixel((x, y), tuple(pixel))

    try:
        encoded_img.save(output_path, format=output_format)
        print(f"\nMessage successfully encoded and saved to '{output_path}' in {output_format} format.")
    except Exception as e:
        raise ImageProcessingError(f"Error saving encoded image to '{output_path}': {e}")

def decode_message(img_path, password=None):
    try:
        img = Image.open(img_path)
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        elif img.mode == 'RGBA':
            print("Warning: Image has an alpha channel. Processing as RGB.")
            img = img.convert('RGB')
    except FileNotFoundError:
        raise FileNotFoundError(f"Error: Encoded image not found at '{img_path}'. Please check the path.")
    except Exception as e:
        raise ImageProcessingError(f"Error opening or processing encoded image '{img_path}': {e}")

    width, height = img.size
    
    pixel_coords = [(x, y) for y in range(height) for x in range(width)]
    
    seed_data = password.encode('utf-8') if password else b'default_stego_seed'
    seed_hash = hashlib.sha256(seed_data).digest()
    random.seed(int.from_bytes(seed_hash[:8], 'big'))
    random.shuffle(pixel_coords)

    # --- Step 1: Read Header (always 1 bit per channel from the randomized stream) ---
    header_binary_parts = []
    current_bit_count = 0
    
    # Max possible header size if salt is max
    max_header_bits_to_read = (len(MAGIC_NUMBER) + 1 + 1 + 1 + SALT_LENGTH + 4) * 8 
    
    header_data_index = 0
    for x, y in pixel_coords:
        if header_data_index >= max_header_bits_to_read:
            break
        pixel = img.getpixel((x, y))
        for i in range(3):
            if header_data_index < max_header_bits_to_read:
                extracted_bit = str(pixel[i] & 1) # Always extract 1 LSB for header
                header_binary_parts.append(extracted_bit)
                header_data_index += 1
        
    full_header_binary = "".join(header_binary_parts)

    # --- Parse Header ---
    try:
        # Minimum header part: Magic (4), BPC (1), Flags (1), SaltLen (1), CRC32 (4) = 11 bytes = 88 bits
        min_header_bytes = len(MAGIC_NUMBER) + 1 + 1 + 1 + 4
        if len(full_header_binary) < min_header_bytes * 8:
            raise HeaderError("Image too small or no complete header found for steganography.")

        header_bytes_raw = bytearray()
        for i in range(0, min_header_bytes * 8, 8):
            header_bytes_raw.append(int(full_header_binary[i:i+8], 2))

        magic_num = header_bytes_raw[0:4]
        if magic_num != MAGIC_NUMBER:
            raise HeaderError("No steganography header found or invalid magic number.")

        extracted_bits_per_channel = struct.unpack('B', header_bytes_raw[4:5])[0]
        flags = struct.unpack('B', header_bytes_raw[5:6])[0]
        salt_length_in_header = struct.unpack('B', header_bytes_raw[6:7])[0]

        current_header_byte_offset = 7
        actual_salt = b''
        if salt_length_in_header > 0:
            salt_bits_start_index = current_header_byte_offset * 8
            salt_bits_end_index = salt_bits_start_index + salt_length_in_header * 8
            
            if len(full_header_binary) < salt_bits_end_index:
                raise HeaderError("Incomplete header: not enough bits for salt.")
            
            salt_binary = full_header_binary[salt_bits_start_index : salt_bits_end_index]
            for i in range(0, len(salt_binary), 8):
                actual_salt += struct.pack('B', int(salt_binary[i:i+8], 2))
            current_header_byte_offset += salt_length_in_header

        crc32_bits_start_index = current_header_byte_offset * 8
        crc32_bits_end_index = crc32_bits_start_index + 4 * 8
        if len(full_header_binary) < crc32_bits_end_index:
            raise HeaderError("Incomplete header: not enough bits for CRC32.")
            
        crc32_binary = full_header_binary[crc32_bits_start_index : crc32_bits_end_index]
        expected_crc32 = struct.unpack('>I', bytes(int(crc32_binary[i:i+8], 2) for i in range(0, len(crc32_binary), 8)))[0]

        is_encrypted = bool(flags & 0b00000001)
        is_compressed = bool(flags & 0b00000010)

        print(f"Header found: Bits per channel = {extracted_bits_per_channel}, Encrypted = {is_encrypted}, Compressed = {is_compressed}")
        if is_encrypted:
            print(f"Salt length: {salt_length_in_header} bytes.")

    except (struct.error, ValueError, IndexError) as e:
        raise HeaderError(f"Failed to parse steganography header: {e}. Image might not be encoded by this tool or is corrupted.")
    except HeaderError as e:
        raise e

    # --- Step 2: Read Message Data (using extracted_bits_per_channel and randomized order) ---
    message_binary_parts = []
    
    # Start reading from where the header bits ended in the randomized stream
    data_index_start = header_data_index # This is the bit index in the overall randomized stream

    total_bits_possible_to_read = (width * height * 3 * extracted_bits_per_channel)
    
    print(f"Reading message data using {extracted_bits_per_channel} bits per channel...")
    pbar_desc = "Decoding message progress"
    
    current_data_index = 0
    null_found = False
    
    with tqdm(total=min(total_bits_possible_to_read - data_index_start, 10_000_000), desc=pbar_desc, unit="bit", leave=True) as pbar:
        for x, y in pixel_coords:
            # Skip pixels that were already used for header extraction
            # This is tricky with randomized order. The simplest is to just re-read the bits
            # but only process them if their index is beyond the header.
            # A more efficient way would be to slice `pixel_coords` after header.
            # But since `tqdm` is used, iterating all and skipping is fine.
            
            pixel = img.getpixel((x, y))
            for i in range(3):
                if current_data_index >= data_index_start: # Only process bits after header
                    extracted_bits = pixel[i] & ((1 << extracted_bits_per_channel) - 1)
                    message_binary_parts.append(format(extracted_bits, '0' + str(extracted_bits_per_channel) + 'b'))
                    
                    pbar.update(extracted_bits_per_channel)
                    if pbar.n >= pbar.total and not null_found:
                        pbar.total += 1_000_000
                        pbar.set_description(f"{pbar_desc} (Extended)")

                    if len(message_binary_parts) * extracted_bits_per_channel >= 8:
                        current_eight_bits_str = "".join(message_binary_parts)[-8:]
                        if current_eight_bits_str == format(ord(NULL_CHAR), '08b'):
                            null_found = True
                            break
                current_data_index += extracted_bits_per_channel # Increment regardless for total index tracking
            if null_found:
                break
        if null_found:
            pass

    if not null_found:
        print("\nWarning: Null terminator not found. The message might be incomplete or corrupted.")

    full_message_binary_str = "".join(message_binary_parts)
    
    null_char_8bit = format(ord(NULL_CHAR), '08b')
    null_index = full_message_binary_str.find(null_char_8bit)
    
    if null_index == -1:
        processed_message_binary = full_message_binary_str
    else:
        processed_message_binary = full_message_binary_str[:null_index]

    extracted_data_bytes = bytearray()
    for i in range(0, len(processed_message_binary), 8):
        byte_str = processed_message_binary[i:i+8]
        if len(byte_str) == 8:
            extracted_data_bytes.append(int(byte_str, 2))

    final_message_bytes = extracted_data_bytes

    if is_encrypted:
        if not password:
            raise PasswordError("Message is encrypted but no password was provided for decryption.")
        try:
            key_for_xor = derive_key(password, actual_salt)
            final_message_bytes = xor_encrypt_decrypt(final_message_bytes, key_for_xor)
            print("Message decrypted.")
        except PasswordError as e:
            raise PasswordError(f"Decryption failed: {e}. Incorrect password or corrupt message?")
        except Exception as e:
            raise PasswordError(f"An unexpected error occurred during decryption: {e}")

    if is_compressed:
        try:
            final_message_bytes = decompress_data(final_message_bytes)
            print("Message decompressed.")
        except ImageProcessingError as e:
            raise ImageProcessingError(f"Decompression failed: {e}. Message might not have been compressed or is corrupted.")
        except Exception as e:
            raise ImageProcessingError(f"An unexpected error occurred during decompression: {e}")

    actual_crc32 = calculate_crc32(final_message_bytes)
    if actual_crc32 != expected_crc32:
        print(f"Warning: Message integrity check failed (CRC32 mismatch). "
              f"Expected {expected_crc32}, Got {actual_crc32}. "
              "Message might be corrupted or tampered with.")
    else:
        print("Message integrity check (CRC32) passed.")

    try:
        decoded_message = final_message_bytes.decode('utf-8')
    except UnicodeDecodeError:
        print("\nWarning: Could not decode message as UTF-8. It might be corrupted or an incorrect password/compression setting was used.")
        decoded_message = final_message_bytes.hex() + " (RAW HEX - could not decode as UTF-8)"

    return decoded_message

if __name__ == "__main__":
    print("--- Welcome to the Advanced Steganography Tool! ---")

    while True:
        print("\nChoose an option:")
        print("1. Encode a message into an image")
        print("2. Decode a message from an image")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, or 3): ").strip()

        if choice == "1":
            img_path = input("Enter the path of the **original** image (e.g., image.png): ").strip()
            
            if not os.path.exists(img_path):
                print(f"Error: The specified image path '{img_path}' does not exist.")
                continue

            message = input("Enter the secret message to encode: ").strip()
            if not message:
                print("Warning: An empty message will be encoded. Are you sure? (y/n)")
                confirm = input().strip().lower()
                if confirm != 'y':
                    continue

            output_path = input("Enter the desired output file name for the encoded image (e.g., encoded_image.png): ").strip()
            if not output_path:
                print("Output file name cannot be empty. Please try again.")
                continue
            
            try:
                bits_per_channel_str = input(f"Enter number of bits per channel (1-8, default: 1): ").strip()
                bits_per_channel_encode = int(bits_per_channel_str) if bits_per_channel_str else 1
                if not (1 <= bits_per_channel_encode <= 8):
                    raise ValueError
            except ValueError:
                print("Invalid input for bits per channel. Using default 1.")
                bits_per_channel_encode = 1

            password_encode = input("Enter a password for encryption (leave empty for no encryption): ").strip()
            
            compress_choice = input("Compress message before embedding? (y/n, default: n): ").strip().lower()
            compress_message = (compress_choice == 'y')

            output_format_choice = input("Enter output image format (PNG, BMP, TIFF, leave empty for PNG): ").strip().upper()
            
            try:
                encode_message(
                    img_path,
                    message,
                    output_path,
                    bits_per_channel=bits_per_channel_encode,
                    password=password_encode if password_encode else None,
                    compress=compress_message,
                    output_format=output_format_choice if output_format_choice else 'PNG'
                )
            except (FileNotFoundError, ImageProcessingError, MessageTooLargeError, ValueError, PasswordError) as e:
                print(f"An error occurred during encoding: {e}")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

        elif choice == "2":
            encoded_img_path = input("Enter the path of the **encoded** image: ").strip()

            if not os.path.exists(encoded_img_path):
                print(f"Error: The specified encoded image path '{encoded_img_path}' does not exist.")
                continue
            
            password_decode = input("Enter the password for decryption (leave empty if not encrypted): ").strip()

            try:
                decoded_message = decode_message(
                    encoded_img_path,
                    password=password_decode if password_decode else None
                )
                print(f"\n--- Decoded message ---")
                print(f"'{decoded_message}'")
                print(f"---------------------")
            except (FileNotFoundError, ImageProcessingError, HeaderError, PasswordError) as e:
                print(f"An error occurred during decoding: {e}")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

        elif choice == "3":
            print("Exiting Steganography Tool. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
