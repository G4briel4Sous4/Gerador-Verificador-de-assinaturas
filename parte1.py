import random
from math import gcd
from hashlib import sha256
from chaves import miller_rabin, generate_prime, mod_inverse, generate_rsa_keys

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Aplica XOR entre dois arrays de bytes."""
    return bytes(x ^ y for x, y in zip(a, b))

def mgf1(seed: bytes, length: int, hash_func=sha256) -> bytes:
    """Mask Generation Function (MGF1) baseada em uma função hash."""
    h_len = hash_func().digest_size
    output = b''
    for counter in range((length + h_len - 1) // h_len):
        C = counter.to_bytes(4, 'big')
        output += hash_func(seed + C).digest()
    return output[:length]

def oaep_encode(message: bytes, seed: bytes, n_bits: int, hash_func=sha256) -> bytes:
    """Codifica a mensagem usando o esquema OAEP."""
    k = (n_bits + 7) // 8  # Tamanho da mensagem em bytes
    h_len = hash_func().digest_size
    
    # Limite para o tamanho da mensagem
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("Mensagem muito grande para o tamanho da chave.")

    # Padding
    ps = b'\x00' * (k - len(message) - 2 * h_len - 2)
    db = hash_func(b'').digest() + ps + b'\x01' + message

    # Gerar máscara para DB
    db_mask = mgf1(seed, len(db), hash_func)
    masked_db = xor_bytes(db, db_mask)

    # Gerar máscara para a semente
    seed_mask = mgf1(masked_db, h_len, hash_func)
    masked_seed = xor_bytes(seed, seed_mask)

    # Construir o bloco codificado
    return b'\x00' + masked_seed + masked_db

def oaep_decode(encoded: bytes, n_bits: int, hash_func=sha256) -> bytes:
    """Decodifica uma mensagem codificada com OAEP."""
    k = (n_bits + 7) // 8
    h_len = hash_func().digest_size

    if len(encoded) != k or encoded[0] != 0:
        raise ValueError("Formato inválido.")

    # Extrair componentes
    masked_seed = encoded[1:h_len + 1]
    masked_db = encoded[h_len + 1:]

    # Reverter máscaras
    seed_mask = mgf1(masked_db, h_len, hash_func)
    seed = xor_bytes(masked_seed, seed_mask)

    db_mask = mgf1(seed, len(masked_db), hash_func)
    db = xor_bytes(masked_db, db_mask)

    # Validar o padding e retornar a mensagem
    l_hash = hash_func(b'').digest()
    if not db.startswith(l_hash):
        raise ValueError("Erro no decodificador OAEP.")

    db = db[len(l_hash):]
    sep_idx = db.index(b'\x01')
    return db[sep_idx + 1:]

def rsa_encrypt(message: bytes, public_key: tuple, n_bits: int) -> bytes:
    """Cifra a mensagem com RSA e OAEP."""
    e, n = public_key
    k = (n_bits + 7) // 8

    # Gerar semente aleatória
    seed = random.randbytes(sha256().digest_size)

    # Codificar a mensagem com OAEP
    encoded_message = oaep_encode(message, seed, n_bits)

    # Converter para inteiro e cifrar com RSA
    m_int = int.from_bytes(encoded_message, byteorder='big')
    c_int = pow(m_int, e, n)

    # Converter o texto cifrado de volta para bytes
    return c_int.to_bytes(k, byteorder='big')

def rsa_decrypt(ciphertext: bytes, private_key: tuple, n_bits: int) -> bytes:
    """Decifra a mensagem cifrada com RSA e OAEP."""
    d, n = private_key
    k = (n_bits + 7) // 8

    # Converter para inteiro e decifrar com RSA
    c_int = int.from_bytes(ciphertext, byteorder='big')
    m_int = pow(c_int, d, n)

    # Converter o texto decifrado de volta para bytes
    encoded_message = m_int.to_bytes(k, byteorder='big')

    # Decodificar a mensagem com OAEP
    return oaep_decode(encoded_message, n_bits)

# Exemplo de uso:
def test_rsa_oaep():
    # Gerar chaves RSA
    public_key, private_key = generate_rsa_keys(bits=1024)
    
    # Mensagem original
    message = b"Mensagem secreta!"
    
    # Cifrar
    ciphertext = rsa_encrypt(message, public_key, 1024)
    
    # Decifrar
    decrypted_message = rsa_decrypt(ciphertext, private_key, 1024)
    
    # Verificar
    print("Mensagem original:", message)
    print("Mensagem decifrada:", decrypted_message)
    print("Cifracao e decifracao OK:", message == decrypted_message)

# Teste
if __name__ == "__main__":
    test_rsa_oaep()
