import random
from hashlib import sha256
from chaves import generate_rsa_keys

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
    encoded_message = oaep_encode(plaintext.encode(), seed, n_bits, hash_function)

    # Converter para inteiro e cifrar
    message_int = int.from_bytes(encoded_message, byteorder='big')
    ciphertext_int = pow(message_int, e, n)
    return ciphertext_int

def rsa_decrypt(ciphertext, private_key, hash_function=sha256):
    """ Decifra a mensagem utilizando a chave privada RSA e remove OAEP """
    d, n = private_key
    n_bits = n.bit_length()

    # Decifrar e converter para bytes
    message_int = pow(ciphertext, d, n)
    encoded_message = message_int.to_bytes((message_int.bit_length() + 7) // 8, byteorder='big')

    # Ajustar comprimento do bloco se necessário
    k = (n_bits + 7) // 8
    if len(encoded_message) < k:
        encoded_message = encoded_message.rjust(k, b'\x00')

    # [DEBUG] Verificar mensagem decifrada antes do decode
    print(f"[DEBUG] encoded_message: {encoded_message.hex()}")

    # Decodificar com OAEP
    plaintext = oaep_decode(encoded_message, n_bits, hash_function)
    return plaintext.decode()

# Função para testar a geração de chaves e cifração/decifração
def test_rsa_encryption():
    public_key, private_key = generate_rsa_keys(bits=1024)

    print("Chave Pública: (e, n)")
    print("e:", public_key[0])
    print("n:", public_key[1])

    print("\nChave Privada: (d, n)")
    print("d:", private_key[0])
    print("n:", private_key[1])

    # Teste de cifração e decifração
    message = "Mensagem Secreta"
    print("\nMensagem original:", message)

    # Cifração
    ciphertext = rsa_encrypt(message, public_key)
    print("Mensagem cifrada:", ciphertext)

    # Decifração
    decrypted_message = rsa_decrypt(ciphertext, private_key)
    print("Mensagem decifrada:", decrypted_message)

# Executando o teste para geração de chaves e cifração/decifração
test_rsa_encryption()
