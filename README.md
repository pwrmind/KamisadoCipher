# Kamisado Cipher 🤫
A custom stream cipher algorithm inspired by the board game Kamisado 🎲

## Introduction 📚
The Kamisado Cipher is a custom stream cipher algorithm designed to provide a secure and efficient way to encrypt and decrypt data. This algorithm is inspired by the board game Kamisado, where players try to outmaneuver each other by moving their pieces strategically 🤔.

## How it works 🤖
The Kamisado Cipher uses a combination of bitwise operations and hash functions to encrypt and decrypt data. Here's a step-by-step overview of the algorithm:

1. **Key Generation** 🔑: A random 256-bit key is generated using a secure random number generator.
2. **Mask Initialization** 📝: The key is hashed using SHA-256, and the first 8 bytes of the hash are used to initialize an array of 8 masks.
3. **Encryption** 🔒:
	* The plaintext is divided into individual bytes.
	* For each byte, a mask is selected based on the current color (initially set to the first byte of the key).
	* The plaintext byte is XORed with the selected mask to produce the ciphertext byte.
	* The mask is updated using a cyclic left shift and XOR operation.
	* The current color is updated with the ciphertext byte.
4. **Decryption** 🔓:
	* The ciphertext is divided into individual bytes.
	* For each byte, a mask is selected based on the current color (initially set to the first byte of the key).
	* The ciphertext byte is XORed with the selected mask to produce the plaintext byte.
	* The mask is updated using a cyclic left shift and XOR operation.
	* The current color is updated with the plaintext byte.

## Example Use Case 📊
Here's an example of how to use the Kamisado Cipher in C#:
```csharp
KamisadoCipher cipher = new KamisadoCipher(key);
byte[] plaintext = Encoding.UTF8.GetBytes("Hello, World!");
var (ciphertext, initialColor) = cipher.Encrypt(plaintext);
byte[] decryptedText = cipher.Decrypt(ciphertext, initialColor);
```
## Security Considerations 🚨
The Kamisado Cipher is a custom algorithm and has not been extensively tested or proven to be secure. It is not recommended to use this algorithm for secure communication without further analysis and validation by cryptography experts.

## Contributing 🤝
If you're interested in contributing to the Kamisado Cipher, please fork this repository and submit a pull request with your changes. Make sure to follow the standard professional guidelines for commit messages and code formatting.

## License 📜
The Kamisado Cipher is licensed under the MIT License. See the LICENSE file for more information.

## Acknowledgments 🙏
The Kamisado Cipher was inspired by the board game Kamisado, created by Peter Burley. Special thanks to the cryptography community for their contributions to the field of cryptography. 💻