import os
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import io
import base64
import argparse


def load_image(image_path):
    try:
        img = Image.open(image_path)
        if img.mode == 'RGBA':
            img = img.convert('RGB')

        #image to bytes
        img_array = np.array(img)
        shape = img_array.shape
        img_bytes = img_array.tobytes()

        return img_bytes, shape, img.mode
    except Exception as e:
        print(f"Error in loading: {e}")
        return None, None, None


def save_image(img_bytes, shape, mode, output_path):
    try:
        img_array = np.frombuffer(img_bytes, dtype=np.uint8).reshape(shape)
        img = Image.fromarray(img_array, mode)
        img.save(output_path)
        print(f"Image saved to {output_path}")
    except Exception as e:
        print(f"Error in saving: {e}")


def encrypt_image(image_path, key, iv, output_path):
    img_bytes, shape, mode = load_image(image_path)
    if img_bytes is None:
        return False

    try:
        if isinstance(key, str):  # Ensure key and IV are in the right format
            key = key.encode()
        if isinstance(iv, str):
            iv = iv.encode()

        cipher = AES.new(key, AES.MODE_CBC, iv)  #AES cipher in CBC mode

        padded_data = pad(img_bytes, AES.block_size)  #Padding the data

        encrypted_data = cipher.encrypt(padded_data)  #encrypt the data

        metadata = {
            'shape': shape,
            'mode': mode,
            'iv': base64.b64encode(iv).decode('utf-8')
        }

        with open(output_path, 'wb') as f:
            metadata_str = str(metadata).encode(
                'utf-8')  #write the metadata as JSON string
            metadata_len = len(metadata_str).to_bytes(4, byteorder='big')
            f.write(metadata_len)
            f.write(metadata_str)

            f.write(encrypted_data)

        print(f"Image encrypted and saved to {output_path}")
        print(f"MODE = 'CBC'")
        print(f"KEY = {key}")
        print(f"IV = {iv}")
        return True

    except Exception as e:
        print(f"Error encrypting image: {e}")
        return False


def decrypt_image(encrypted_path, key, iv, output_path):
    try:
        if isinstance(key, str):
            key = key.encode()
        if isinstance(iv, str):
            iv = iv.encode()

        with open(encrypted_path, 'rb') as f:
            metadata_len = int.from_bytes(f.read(4), byteorder='big')

            metadata_str = f.read(metadata_len).decode('utf-8')
            metadata = eval(metadata_str)  # Convert string back to dict

            shape = metadata['shape']
            mode = metadata['mode']

            if iv is None and 'iv' in metadata:
                iv = base64.b64decode(metadata['iv'])

            encrypted_data = f.read()  #Read the data

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_padded = cipher.decrypt(encrypted_data)  #Decrypt data

        decrypted_data = unpad(decrypted_padded,
                               AES.block_size)  # Remove padding

        save_image(decrypted_data, shape, mode,
                   output_path)  #Save the decrypted image
        return True

    except Exception as e:
        print(f"Error decrypting image: {e}")
        return False


def generate_key():
    """Generate a random 16-byte key for AES-128."""
    return os.urandom(16)


def generate_iv():
    """Generate a random 16-byte initialization vector."""
    return os.urandom(16)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt images using AES-CBC")
    parser.add_argument("--action",
                        choices=["encrypt", "decrypt"],
                        required=True,
                        help="Action to perform")
    parser.add_argument("--input", required=True, help="Input image path")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--key",
                        help="Encryption/decryption key (16, 24, or 32 bytes)")
    parser.add_argument("--iv", help="Initialization vector (16 bytes)")
    parser.add_argument("--generate-key",
                        action="store_true",
                        help="Generate a random key")
    parser.add_argument("--generate-iv",
                        action="store_true",
                        help="Generate a random IV")

    args = parser.parse_args()

    # Handle key
    if args.generate_key:
        key = generate_key()
        print(f"Generated key: {key}")
    elif args.key:
        try:
            key = bytes.fromhex(
                args.key) if args.key.startswith("0x") else args.key.encode()
            if len(key) not in [16, 24, 32]:
                print(
                    f"Key must be 16, 24, or 32 bytes long. Current length: {len(key)}"
                )
                exit(1)
        except Exception as e:
            print(f"Error processing key: {e}")
            exit(1)
    else:
        print(
            "Error: Either provide a key with --key or use --generate-key to create a random one"
        )
        exit(1)

    # Handle IV
    if args.generate_iv:
        iv = generate_iv()
        print(f"Generated IV: {iv}")
    elif args.iv:
        try:
            iv = bytes.fromhex(
                args.iv) if args.iv.startswith("0x") else args.iv.encode()
            if len(iv) != 16:
                print(f"IV must be 16 bytes long. Current length: {len(iv)}")
                exit(1)
        except Exception as e:
            print(f"Error processing IV: {e}")
            exit(1)
    else:
        if args.action == "encrypt":
            print(
                "Error: Either provide an IV with --iv or use --generate-iv to create a random one"
            )
            exit(1)
        else:
            iv = None

    # Start the action
    if args.action == "encrypt":
        encrypt_image(args.input, key, iv, args.output)
    else:  # decrypt
        decrypt_image(args.input, key, iv, args.output)
