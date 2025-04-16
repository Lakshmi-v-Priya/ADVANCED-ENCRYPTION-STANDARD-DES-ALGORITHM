# EX-4-ADVANCED-ENCRYPTION-STANDARD-DES-ALGORITHM

## Aim:
  To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

## ALGORITHM: 
  1. AES is based on a design principle known as a substitution–permutation. 
  2. AES does not use a Feistel network like DES, it uses variant of Rijndael. 
  3. It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. 
  4. AES operates on a 4 × 4 column-major order array of bytes, termed the state

## PROGRAM: 
```
def simple_aes_encrypt(plaintext, key):
    ciphertext = ''
    for i in range(len(plaintext)):
        ciphertext += chr(ord(plaintext[i]) ^ ord(key[i % len(key)]))
    return ciphertext

def simple_aes_decrypt(ciphertext, key):
    decrypted_text = ''
    for i in range(len(ciphertext)):
        decrypted_text += chr(ord(ciphertext[i]) ^ ord(key[i % len(key)]))
    return decrypted_text

def print_ascii(ciphertext):
    print("Encrypted Message (ASCII values): ", end='')
    for c in ciphertext:
        print(ord(c), end=' ')
    print()

def main():
    plaintext = input("Enter the plaintext: ")
    key = input("Enter the key: ")

    ciphertext = simple_aes_encrypt(plaintext, key)
    print_ascii(ciphertext)

    decrypted_text = simple_aes_decrypt(ciphertext, key)
    print(f"Decrypted Message: {decrypted_text}")

if __name__ == "__main__":
    main()
```
## OUTPUT:
![image](https://github.com/user-attachments/assets/b059aa96-f1c5-4f58-980d-edbe87b304ff)

## RESULT: 
Hence,to use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption is done successfully.
