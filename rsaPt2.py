import random
from hashlib import sha256
from chaves import generate_rsa_keys

# --- Funções de suporte OAEP (sem mudanças) ---
def mgf1(seed, mask_len, hash_function=sha256):
    h_len = hash_function().digest_size
    mask = b''
    for counter in range((mask_len + h_len - 1) // h_len):
        C = counter.to_bytes(4, byteorder='big')
        mask += hash_function(seed + C).digest()
    return mask[:mask_len]

def oaep_encode(message, seed, n_bits, hash_function=sha256):
    k = (n_bits + 7) // 8
    h_len = hash_function().digest_size
    max_message_length = k - 2 * h_len - 2

    if len(message) > max_message_length:
        raise ValueError("Mensagem muito longa para o tamanho da chave.")

    l_hash = hash_function(b'').digest()
    ps = b'\x00' * (max_message_length - len(message))
    db = l_hash + ps + b'\x01' + message
    db_mask = mgf1(seed, len(db), hash_function)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, h_len, hash_function)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    return b'\x00' + masked_seed + masked_db

def oaep_decode(encoded_message, n_bits, hash_function=sha256):
    k = (n_bits + 7) // 8
    h_len = hash_function().digest_size

    if len(encoded_message) != k or encoded_message[0] != 0:
        raise ValueError("Formato inválido para OAEP.")

    masked_seed = encoded_message[1:h_len + 1]
    masked_db = encoded_message[h_len + 1:]
    seed_mask = mgf1(masked_db, h_len, hash_function)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, len(masked_db), hash_function)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    l_hash = hash_function(b'').digest()
    if not db.startswith(l_hash):
        raise ValueError("OAEP decode falhou: hash não corresponde.")

    db = db[len(l_hash):]
    separator_idx = db.index(b'\x01')
    message = db[separator_idx + 1:]
    return message

# --- Funções RSA ajustadas ---
def rsa_encrypt(plaintext, public_key, hash_function=sha256):
    e, n = public_key
    n_bits = n.bit_length()
    h_len = hash_function().digest_size
    seed = random.randbytes(h_len)

    encoded_message = oaep_encode(plaintext, seed, n_bits, hash_function)
    message_int = int.from_bytes(encoded_message, byteorder='big')
    ciphertext_int = pow(message_int, e, n)
    return ciphertext_int

def rsa_decrypt(ciphertext, private_key, hash_function=sha256):
    d, n = private_key
    n_bits = n.bit_length()
    message_int = pow(ciphertext, d, n)
    encoded_message = message_int.to_bytes((message_int.bit_length() + 7) // 8, byteorder='big')

    k = (n_bits + 7) // 8
    if len(encoded_message) < k:
        encoded_message = encoded_message.rjust(k, b'\x00')

    plaintext = oaep_decode(encoded_message, n_bits, hash_function)
    return plaintext

# --- Função de teste ---
def test_rsa_encryption():
    public_key, private_key = generate_rsa_keys(bits=1024)
    print("Chave Pública:", public_key)
    print("Chave Privada:", private_key)

    message = b"Bia"
    print("\nMensagem original:", message)

    ciphertext = rsa_encrypt(message, public_key)
    print("\nMensagem cifrada:", ciphertext)

    decrypted_message = rsa_decrypt(ciphertext, private_key)
    print("\nMensagem decifrada:", decrypted_message.decode())

# --- Executar teste ---
test_rsa_encryption()
