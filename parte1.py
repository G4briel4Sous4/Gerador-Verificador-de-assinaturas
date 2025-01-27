from chaves import miller_rabin, generate_prime, mod_inverse, generate_rsa_keys
import random
from hashlib import sha256

# Função auxiliar para gerar máscara
def mgf1(seed: bytes, length: int, hash_function=sha256):
    """
    Gera uma máscara de tamanho `length` usando MGF1 com base na `seed` e a função de hash especificada.
    """
    mask = b''
    counter = 0
    while len(mask) < length:
        counter_bytes = counter.to_bytes(4, byteorder='big')
        mask += hash_function(seed + counter_bytes).digest()
        counter += 1
    return mask[:length]

# Implementação do OAEP

def oaep_pad(message: bytes, n_bits: int, label: bytes = b"", hash_function=sha256):
    """
    Aplica OAEP (Optimal Asymmetric Encryption Padding) à mensagem fornecida.
    
    :param message: Mensagem original em bytes.
    :param n_bits: Tamanho de n (módulo RSA) em bits.
    :param label: Rótulo opcional, padrão vazio.
    :param hash_function: Função de hash a ser usada, padrão SHA-256.
    :return: Mensagem preenchida (padded).
    """
    k = (n_bits + 7) // 8  # Tamanho de n em bytes
    h_len = hash_function().digest_size

    # Verificar se a mensagem é grande demais
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("Mensagem muito longa para o módulo dado.")

    # Hash do rótulo
    l_hash = hash_function(label).digest()

    # Gerar padding e blocos
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message

    # Gerar semente aleatória
    seed = random.randbytes(h_len)

    # Gerar máscaras
    db_mask = mgf1(seed, len(db), hash_function)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    seed_mask = mgf1(masked_db, h_len, hash_function)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    # Montar a mensagem preenchida
    return b"\x00" + masked_seed + masked_db


def rsa_encrypt(message: bytes, public_key: tuple, oaep_label: bytes = b"", hash_function=sha256):
    e, n = public_key
    n_bits = n.bit_length()

    # Aplicar OAEP
    padded_message = oaep_pad(message, n_bits, oaep_label, hash_function)
    print("Padded Message: ", padded_message)
    print("Tamanho paddedMessage: ", len(padded_message))
    print("Tamanho da publicKey: ", public_key[1].bit_length())  # Deve retornar 1024

    # Converter a mensagem preenchida para inteiro
    m_int = int.from_bytes(padded_message, byteorder="big")

    # Cifrar com RSA
    if m_int >= n:
        raise ValueError("Mensagem após OAEP é muito grande para o módulo RSA.")

    c_int = pow(m_int, e, n)  # Cifração RSA

    # Converter o inteiro cifrado para bytes, garantindo o comprimento correto
    ciphertext = c_int.to_bytes((c_int.bit_length() + 7) // 8, byteorder='big')

    return ciphertext



# Exemplo de uso com chaves geradas
def test_rsa_encrypt():
    public_key, private_key = generate_rsa_keys(bits=1024)
    message = b"Mensagem de teste para RSA com OAEP"

    print("Mensagem original:", message)
    
    # Criptografar
    ciphertext = rsa_encrypt(message, public_key)
    print("Mensagem cifrada (int):", ciphertext)

test_rsa_encrypt()
