# License Checker and Generator

## Functionality

- Generate a license signed by a private key. 
- Check the license based on the public key.

## Design

Use two Private keys (K1, K2) for licensing as follows.
- Use K1's private key to encrypt the license information.
- Use K2's private key to sign that information.
- Bundle both K1's private key and K2's public key with the application.
- When decrypting K1's private key will be used, and then signature will be
  checked using the public key of K2.
