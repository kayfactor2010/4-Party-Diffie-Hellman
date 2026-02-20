# Four-Party Diffie–Hellman Key Exchange
This project implements a multi-party extension of the classical Diffie–Hellman key exchange protocol, enabling four participants to securely derive a shared secret over an insecure channel.
The project demonstrates practical implementation of public-key cryptography principles and explores the scalability and correctness challenges introduced by multi-party key exchange.

# How It Works

1. A large prime and generator are agreed upon.
2. Each participant selects a private key.
3. Public keys are computed using modular exponentiation.
4. Intermediate values are exchanged sequentially.
5. Each participant performs further exponentiation to derive the final shared secret.

The implementation ensures that all four parties derive the same final key

# Implementation Details

- Language: Java 
- Modular exponentiation used to prevent overflow
- Object-oriented structure to model individual participants
- Validation checks confirm shared secret consistency
