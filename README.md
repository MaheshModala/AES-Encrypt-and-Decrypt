# AES-Encrypt-and-Decrypt
Image Encryption/Decryption Suite using AES-CBC
This code allows you to encrypt and decrypt images using AES in CBC mode. Please find the key and iv below:

**MODE = 'CBC'
KEY = b'ThanksToAndyNovo'
IV = b'9346450557810662'**

Required packages: **pip install pillow numpy pycryptodome**
Here is a quick overview of how to use the code:
First, please download my code and encrypted image attached to this repo to the same folder.
To Decrypt my encrypted image, run the below action in the same path as the code: 
**python Aes_CBC_Crypto.py --action decrypt --input encrypted.img --output decrypted.jpg --key "ThanksToAndyNovo" --iv "9346450557810662"**

Quick writeup:
I focused on implementing AES in CBC mode as it provides better security than ECB through an initialization vector. This prevents identical plaintext blocks from producing identical ciphertext blocks.
It took nearly 4 to 5 days with some breaks in between to complete this project. Thanks to your video lecture recordings for a brief overview of how things work. I was not able to attend for the live sessions, because I had some offline classes at the same time. Learned a lot about modern crypto by watching your recordings.
Initially struggled with ECB mode producing corrupted outputs due to improper padding. Spent 1 day debugging before realizing image data needed proper block alignment. Breakthrough came when implementing CBC with IV, which handled padding better.
The key challenges I addressed were:
**Converting image data to a format suitable for encryption.
Storing and retrieving metadata needed for reconstruction.**

I'm proud of this work because it helped me to overcome initial failures to produce working code. My only regret is not adding more error handling. The experience was challenging but rewarding.
Working on this project has reinforced several important cryptography concepts:
The importance of initialization vectors in block ciphers.
How proper padding is crucial for security.
Why metadata management is essential for encrypted files.
The biggest insight is understanding how cryptographic modes like CBC provide much better security than simpler modes like ECB, especially for image data where patterns would otherwise be visible in the encrypted output.
CBC mode provides good security for most applications, but for truly nation-state level security: The key management would need to be more robust, and using AES-256 (with a 32-byte key) would be preferable to AES-128. For true nation-state security, I'd recommend CTR mode.
