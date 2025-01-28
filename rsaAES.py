import os
from Crypto.Cipher import AES
from hashlib import sha256
from chaves import generate_rsa_keys
from rsaOAEP import rsa_encrypt, rsa_decrypt

def generate_aes_key(key_size=256):
    """Gera uma chave simétrica para AES."""
    return os.urandom(key_size // 8)

def aes_encrypt(message, key):
    """Cifra uma mensagem usando AES no modo GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, key):
    """Decifra uma mensagem cifrada com AES no modo GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except ValueError:
        raise ValueError("Falha na decifração ou verificação da integridade.")

def hybrid_encrypt(message, public_key):
    """Realiza a cifragem híbrida usando RSA e AES.

    Args:
        message (str): Mensagem a ser cifrada.
        public_key (tuple): Chave pública RSA (e, n).

    Returns:
        dict: Contém a chave cifrada, nonce, ciphertext e tag.
    """
    # Gerar chave simétrica AES
    aes_key = generate_aes_key()

    # Cifrar mensagem com AES
    nonce, ciphertext, tag = aes_encrypt(message, aes_key)

    # Cifrar chave AES com RSA
    encrypted_key = rsa_encrypt(aes_key, public_key)

    return {
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag
    }

def hybrid_decrypt(encrypted_data, private_key):
    """Realiza a decifragem híbrida usando RSA e AES.

    Args:
        encrypted_data (dict): Dados cifrados contendo a chave, nonce, ciphertext e tag.
        private_key (tuple): Chave privada RSA (d, n).

    Returns:
        str: Mensagem decifrada.
    """
    # Decifrar chave AES com RSA
    encrypted_key = encrypted_data["encrypted_key"]
    aes_key = rsa_decrypt(encrypted_key, private_key)

    # Decifrar mensagem com AES
    nonce = encrypted_data["nonce"]
    ciphertext = encrypted_data["ciphertext"]
    tag = encrypted_data["tag"]
    plaintext = aes_decrypt(nonce, ciphertext, tag, aes_key)

    return plaintext

# Testando a cifragem e decifragem híbrida
def test_hybrid_encryption():
    public_key, private_key = generate_rsa_keys(bits=1024)

    print("Chave Pública: (e, n)")
    print("e:", public_key[0])
    print("n:", public_key[1])

    print("\nChave Privada: (d, n)")
    print("d:", private_key[0])
    print("n:", private_key[1])

    # Mensagem para teste
    message = "Mensagem secreta para cifragem híbrida"
    print("\nMensagem original:", message)

    # Cifragem híbrida
    encrypted_data = hybrid_encrypt(message, public_key)
    print("\nDados cifrados:")
    print("Chave cifrada:", encrypted_data["encrypted_key"])
    print("Nonce:", encrypted_data["nonce"].hex())
    print("Ciphertext:", encrypted_data["ciphertext"].hex())
    print("Tag:", encrypted_data["tag"].hex())

    # Decifragem híbrida
    decrypted_message = hybrid_decrypt(encrypted_data, private_key)
    print("\nMensagem decifrada:", decrypted_message)

# Executando o teste
test_hybrid_encryption()
