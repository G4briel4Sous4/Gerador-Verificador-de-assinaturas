from hashlib import sha256
from chaves import miller_rabin, generate_prime, mod_inverse, generate_rsa_keys
import random

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
    print("Entrando na função oaep_pad.")
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

    print("DB gerado:", db)

    # Gerar semente aleatória
    seed = random.randbytes(h_len)
    print("Semente gerada:", seed)

    # Gerar máscaras
    db_mask = mgf1(seed, len(db), hash_function)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    print("DB mascarado:", masked_db)

    seed_mask = mgf1(masked_db, h_len, hash_function)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    print("Semente mascarada:", masked_seed)

    # Montar a mensagem preenchida
    padded_message = b"\x00" + masked_seed + masked_db
    print("Mensagem preenchida:", padded_message)
    return padded_message

def rsa_encrypt(message: bytes, public_key: tuple, oaep_label: bytes = b"", hash_function=sha256):
    print("Iniciando criptografia RSA.")
    e, n = public_key
    n_bits = n.bit_length()

    # Aplicar OAEP
    padded_message = oaep_pad(message, n_bits, oaep_label, hash_function)
    print("Padded Message após OAEP: ", padded_message)
    print("Tamanho paddedMessage: ", len(padded_message))
    print("Tamanho da publicKey: ", n_bits)  # Verifica o tamanho da chave pública

    # Converter a mensagem preenchida para inteiro
    m_int = int.from_bytes(padded_message, byteorder="big")
    print("Mensagem convertida para inteiro:", m_int)

    # Cifrar com RSA
    if m_int >= n:
        raise ValueError("Mensagem após OAEP é muito grande para o módulo RSA.")

    c_int = pow(m_int, e, n)  # Cifração RSA
    print("Cifra gerada:", c_int)

    # Converter o inteiro cifrado para bytes, garantindo o comprimento correto
    ciphertext = c_int.to_bytes((c_int.bit_length() + 7) // 8, byteorder='big')
    print("Mensagem cifrada (em bytes):", ciphertext)

    return ciphertext


def rsa_decrypt(ciphertext: bytes, private_key: tuple, n_bits: int, oaep_label: bytes = b"", hash_function=sha256):
    print("Iniciando descriptografia RSA.")
    decrypted_message = oaep_unpad(ciphertext, n_bits, private_key, oaep_label, hash_function)
    
    # Verifique se a mensagem decifrada é de tipo 'bytes'
    if isinstance(decrypted_message, bytes):
        try:
            decrypted_message_str = decrypted_message.decode('utf-8')  # Decodifique para UTF-8
        except UnicodeDecodeError:
            decrypted_message_str = decrypted_message.decode('ISO-8859-1')  # Tenta ISO-8859-1 se UTF-8 falhar
            print("Decodificação com 'ISO-8859-1' em vez de UTF-8.")
    else:
        decrypted_message_str = decrypted_message  # Se já for uma string, use diretamente
    
    print("Mensagem decifrada:", decrypted_message_str)
    return decrypted_message_str


def oaep_unpad(ciphertext: bytes, n_bits: int, private_key: tuple, label: bytes = b"", hash_function=sha256):
    print("Entrando na função oaep_unpad.")
    k = (n_bits + 7) // 8  # Tamanho de n em bytes
    h_len = hash_function().digest_size

    # Converter a cifra para inteiro
    c_int = int.from_bytes(ciphertext, byteorder='big')
    print("Cifra convertida para inteiro:", c_int)

    # Desfazer a operação RSA
    m_int = pow(c_int, private_key[0], private_key[1])  # m_int = c^d mod n
    print("Inteiro após a operação RSA:", m_int)

    # Converter de volta para bytes
    padded_message = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big')
    print("Mensagem após desfazer RSA (padded):", padded_message)

    # Extrair as partes da mensagem preenchida
    masked_seed = padded_message[1:h_len+1]
    masked_db = padded_message[h_len+1:]
    print("Masked Seed:", masked_seed)
    print("Masked DB:", masked_db)

    # Aplicar a máscara MGF1
    seed_mask = mgf1(masked_db, h_len, hash_function)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    print("Seed após máscara MGF1:", seed)

    db_mask = mgf1(seed, len(masked_db), hash_function)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    print("DB após máscara MGF1:", db)

    # Dividir o db em l_hash + ps + 0x01 + mensagem
    l_hash = db[:h_len]
    ps = db[h_len:-1]
    message = db[-len(ps):]  # Corrigido para pegar a mensagem após o padding

    print("Mensagem extraída:", message)
    return message


def test_rsa_decrypt():
    print("Iniciando o teste de criptografia e descriptografia.")
    public_key, private_key = generate_rsa_keys(bits=1024)
    message = b"Mensagem de teste para RSA com OAEP"

    print("Mensagem original:", message)
    
    # Criptografar
    ciphertext = rsa_encrypt(message, public_key)
    print("Mensagem cifrada:", ciphertext)
    
    # Descriptografar
    decrypted_message = rsa_decrypt(ciphertext, private_key, public_key[1].bit_length())
    print("Mensagem decifrada:", decrypted_message)  # Já é uma string

test_rsa_decrypt()
