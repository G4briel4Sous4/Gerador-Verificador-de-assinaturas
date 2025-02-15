import random
from hashlib import sha256
from Crypto.Random import get_random_bytes
from chaves import generate_rsa_keys
import base64
import ecb

def mgf1(seed, mask_len, hash_function=sha256):
    """ Gerador de máscara MGF1 baseado no hash fornecido """
    h_len = hash_function().digest_size
    mask = b''
    for counter in range((mask_len + h_len - 1) // h_len):
        C = counter.to_bytes(4, byteorder='big')
        mask += hash_function(seed + C).digest()
    return mask[:mask_len]

def oaep_encode(message, seed, n_bits, hash_function=sha256):
    """ Codifica a mensagem usando OAEP """
    k = (n_bits + 7) // 8  # Tamanho do módulo em bytes
    h_len = hash_function().digest_size

    # Calcular comprimento máximo de mensagem suportada
    max_message_length = k - 2 * h_len - 2
    if len(message) > max_message_length:
        raise ValueError("Mensagem muito longa para o tamanho da chave.")

    # Gerar os blocos
    l_hash = hash_function(b'').digest()  # Suporte a label vazia
    ps = b'\x00' * (max_message_length - len(message))
    db = l_hash + ps + b'\x01' + message
    
    # Gerar máscara para DB
    db_mask = mgf1(seed, len(db), hash_function)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    # Gerar máscara para o seed
    seed_mask = mgf1(masked_db, h_len, hash_function)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    # Construir o bloco codificado
    return b'\x00' + masked_seed + masked_db

def oaep_decode(encoded_message, n_bits, hash_function=sha256):
    """ Decodifica a mensagem codificada usando OAEP """
    k = (n_bits + 7) // 8
    h_len = hash_function().digest_size

    # Verificar o comprimento do bloco
    if len(encoded_message) != k or encoded_message[0] != 0:
        print(f"[DEBUG] Comprimento do bloco: {len(encoded_message)}, esperado: {k}")
        print(f"[DEBUG] Primeiro byte: {encoded_message[0]}")
        raise ValueError("Formato inválido para OAEP.")

    # Separar os blocos
    masked_seed = encoded_message[1:h_len + 1]
    masked_db = encoded_message[h_len + 1:]

    # Gerar máscara para o seed
    seed_mask = mgf1(masked_db, h_len, hash_function)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    # Gerar máscara para DB
    db_mask = mgf1(seed, len(masked_db), hash_function)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    # [DEBUG] Verificar valores intermediários
    print(f"[DEBUG] seed: {seed.hex()}")
    print(f"[DEBUG] db: {db.hex()}")

    # Extrair l_hash, PS e mensagem
    l_hash = hash_function(b'').digest()
    if not db.startswith(l_hash):
        print(f"[DEBUG] l_hash esperado: {l_hash.hex()}")
        print(f"[DEBUG] l_hash obtido: {db[:len(l_hash)].hex()}")
        raise ValueError("OAEP decode falhou: hash não corresponde.")

    db = db[len(l_hash):]  # Remover l_hash
    separator_idx = db.index(b'\x01')
    message = db[separator_idx + 1:]
    return message

# Modificar as funções de cifração RSA para usar OAEP
def rsa_encrypt(plaintext, public_key, hash_function=sha256):
    """ Cifra a mensagem utilizando OAEP e a chave pública RSA """
    e, n = public_key
    n_bits = n.bit_length()

    # Gerar seed aleatório para OAEP
    k = (n_bits + 7) // 8
    h_len = hash_function().digest_size
    seed = random.randbytes(h_len)

    # Codificar com OAEP
    encoded_message = oaep_encode(plaintext, seed, n_bits, hash_function)  # Remover .encode()

    # Converter para inteiro e cifrar
    message_int = int.from_bytes(encoded_message, byteorder='big')
    ciphertext_int = pow(message_int, e, n)
    return ciphertext_int


def rsa_decrypt(ciphertext, private_key, hash_function=sha256):
    """ Decifra a mensagem utilizando a chave privada RSA e remove OAEP """
    d, n = private_key
    n_bits = n.bit_length()

    # Converter o ciphertext (que está em bytes) para inteiro
    ciphertext_int = int.from_bytes(ciphertext, byteorder='big')

    # Decifrar o inteiro com a chave privada
    message_int = pow(ciphertext_int, d, n)

    # Converter de volta para bytes
    encoded_message = message_int.to_bytes((message_int.bit_length() + 7) // 8, byteorder='big')

    # Ajustar comprimento do bloco se necessário
    k = (n_bits + 7) // 8
    if len(encoded_message) < k:
        encoded_message = encoded_message.rjust(k, b'\x00')

    # Decodificar com OAEP
    plaintext = oaep_decode(encoded_message, n_bits, hash_function)

    # Verificar se a mensagem precisa ser tratada como base64
    try:
        # Tenta decodificar como base64
        return base64.b64decode(plaintext).decode()
    except Exception:
        # Se falhar, retorna a mensagem binária (pode ser chave AES ou outro dado)
        return plaintext

# Função para gerar chave AES
def generate_aes_key():
    return get_random_bytes(32) 

def convert_to_decimal_blocks_from_bytes(byte_sequence, block_size=4):
    # Inicializar uma lista para armazenar os blocos
    blocks = []

    # Dividir a sequência de bytes em blocos de 16 bytes (4 sub-blocos de 4 bytes)
    for i in range(0, len(byte_sequence), block_size * 4):
        block = byte_sequence[i:i + block_size * 4]  # Pega 16 bytes
        # Dividir esse bloco de 16 bytes em 4 sub-blocos de 4 bytes
        sub_blocks = [list(block[j:j + block_size]) for j in range(0, len(block), block_size)]
        blocks.append(sub_blocks)

    return blocks


def convert_to_bytes(blocks):
    # Inicializar uma lista para armazenar os bytes
    byte_sequence = b''
    
    # Iterar sobre cada bloco
    for block in blocks:
        for sub_block in block:
            # Para cada sub-bloco (lista de 4 valores), convertê-los para bytes
            byte_sequence += bytes(sub_block)
    
    return byte_sequence

def convert_to_decimal_blocks(padded_message):
    # Converter a mensagem para uma lista de inteiros decimais
    decimal_values = list(padded_message)
    
    # Garantir que a lista tenha um tamanho múltiplo de 16 para dividir em blocos de 128 bits
    # Criando blocos de 16 bytes (128 bits) e dividindo em sublistas de 4 elementos
    blocks = [decimal_values[i:i + 4] for i in range(0, len(decimal_values), 4)]
    
    # Agrupar os blocos de 16 bytes em blocos de 128 bits (4 valores por linha)
    grouped_blocks = [blocks[i:i + 4] for i in range(0, len(blocks), 4)]

    return grouped_blocks

def aes_encrypt(key, message):
    
    padded_message = message + (16 - len(message) % 16) * b'\x00'

    blocks = convert_to_decimal_blocks(padded_message)

    cifrado = ecb.ecb_encrypt(blocks, key)

    em_bytes = convert_to_bytes(cifrado)

    return em_bytes

# Função para decifrar uma mensagem com AES no modo ECB
def aes_decrypt(key, ciphertext):

    converted =  convert_to_decimal_blocks_from_bytes(ciphertext)

    padded_message = ecb.ecb_decrypt(converted, key)

    byte_message = convert_to_bytes(padded_message)

    return byte_message.rstrip(b'\x00') 


# Função para cifrar a chave AES com a chave pública RSA
def rsa_aes_key_encrypt(public_key, aes_key):
    """ Cifra a chave AES usando a chave pública RSA """
    return rsa_encrypt(aes_key, public_key)

# Função para decifrar a chave AES com a chave privada RSA
def rsa_aes_key_decrypt(private_key, encrypted_aes_key):
    """ Decifra a chave AES usando a chave privada RSA """
    return rsa_decrypt(encrypted_aes_key, private_key)

# Função principal para cifração híbrida
def hybrid_encryption(message, public_key):
    """ Realiza a cifração híbrida (RSA + AES) """
    # 1. Gerar chave AES
    aes_key = generate_aes_key()

    # 2. Cifrar a mensagem com AES
    ciphertext_aes = aes_encrypt(aes_key, message.encode())

    # 3. Cifrar a chave AES com a chave pública RSA
    encrypted_aes_key = rsa_aes_key_encrypt(public_key, aes_key)

    # 4. Converter a chave AES cifrada para bytes e codificar em base64
    encrypted_aes_key_bytes = encrypted_aes_key.to_bytes((encrypted_aes_key.bit_length() + 7) // 8, byteorder='big')
    
    # 5. Retornar a chave AES cifrada e a mensagem cifrada
    return base64.b64encode(encrypted_aes_key_bytes).decode(), base64.b64encode(ciphertext_aes).decode()


# Função para decifração híbrida
def hybrid_decryption(encrypted_aes_key_b64, ciphertext_aes_b64, private_key):
    """ Realiza a decifração híbrida (RSA + AES) """
    # 1. Decifrar a chave AES com a chave privada RSA
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    aes_key = rsa_aes_key_decrypt(private_key, encrypted_aes_key)

    # 2. Decifrar a mensagem com AES
    ciphertext_aes = base64.b64decode(ciphertext_aes_b64)

    decrypted_message = aes_decrypt(aes_key, ciphertext_aes)

    return decrypted_message.decode()

# Teste de cifração e decifração híbrida
def test_hybrid_encryption():
    # Gerar chaves RSA
    public_key, private_key = generate_rsa_keys(bits=1024)

    print("Chave Pública RSA: (e, n)")
    print("e:", public_key[0])
    print("n:", public_key[1])

    print("\nChave Privada RSA: (d, n)")
    print("d:", private_key[0])
    print("n:", private_key[1])

    # Mensagem a ser cifrada
    message = "Mensagem Secreta"
    print("\nMensagem original:", message)

    # Cifração Híbrida
    encrypted_aes_key_b64, ciphertext_aes_b64 = hybrid_encryption(message, public_key)
    print("\nChave AES cifrada (RSA):", encrypted_aes_key_b64)
    print("Mensagem cifrada com AES:", ciphertext_aes_b64)

    # Decifração Híbrida
    decrypted_message = hybrid_decryption(encrypted_aes_key_b64, ciphertext_aes_b64, private_key)
    print("\nMensagem decifrada:", decrypted_message)

# Executando o teste
test_hybrid_encryption()
