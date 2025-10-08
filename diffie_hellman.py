# Diffie-Hellman Key Exchange (simple Python program)
# - Shows key generation, exchange of public values, shared secret computation
# - Demonstrates deriving a symmetric key via SHA-256 of the shared secret
# Note: For real-world security use standardized large primes (RFC groups) and vetted libraries.

import secrets
import hashlib

def generate_private_key(bits=256):
    """Generate a cryptographically-random private key of given bit length."""
    return secrets.randbits(bits)

def compute_public_key(private_key, a, q):
    """Compute public key A = a^private_key mod q."""
    return pow(a, private_key, q)

def compute_shared_secret(peer_public, private_key, q):
    """Compute shared secret s = peer_public^private_key mod q."""
    return pow(peer_public, private_key, q)

def derive_key(shared_secret):
    """Derive a symmetric key from the integer shared secret using SHA-256 (hex)."""
    ss_bytes = shared_secret.to_bytes((shared_secret.bit_length()+7)//8 or 1, 'big')
    return hashlib.sha256(ss_bytes).hexdigest()


if __name__ == "__main__":
    # Small illustrative example (insecure because p is tiny) -- good for learning
    q = 353   # prime modulus (tiny for demo)
    a = 3        # primitive root
    print("Demonstration with small parameters (INSECURE for real use):")
    print("q =", q, "a =", a)

    # Alice and Bob choose private keys
    a_priv = generate_private_key(bits=6) 
    b_priv = generate_private_key(bits=6)

    # Compute public keys
    A_pub = compute_public_key(a_priv, a, q)
    B_pub = compute_public_key(b_priv, a, q)

    # Exchange and compute shared secret
    A_shared = compute_shared_secret(B_pub, a_priv, q)
    B_shared = compute_shared_secret(A_pub, b_priv, q)

    print("Alice private:", a_priv)
    print("Bob   private:", b_priv)
    print("Alice public A =", A_pub)
    print("Bob   public B =", B_pub)
    print("Alice shared secret:", A_shared)
    print("Bob   shared secret:  ", B_shared)
    print("Shared equal?", A_shared == B_shared)
    print("Derived symmetric key (SHA-256):", derive_key(A_shared))
    print()

