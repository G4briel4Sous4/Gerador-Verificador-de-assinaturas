from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PublicFormat, PrivateFormat, NoEncryption

# Parte 1: Geração de Chaves (p e q primos com no mínimo 1024 bits)
def generate_keys():
    # Gera a chave privada com tamanho de 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Valor padrão recomendado para e
        key_size=2048          # Tamanho mínimo recomendado é 2048 bits
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Salva as chaves em arquivos
def save_keys(private_key, public_key):
    # Salvar a chave privada em formato PEM
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))

    # Salvar a chave pública em formato PEM
    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ))

# Parte 2: Cifração Assimétrica RSA usando OAEP
def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Parte 2: Decifração Assimétrica RSA usando OAEP
def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Testando o código
if __name__ == "__main__":
    # Geração das chaves
    private_key, public_key = generate_keys()
    save_keys(private_key, public_key)

    # Mensagem a ser cifrada
    message = "Este é um teste de RSA com OAEP."
    print(f"Mensagem original: {message}")

    # Cifração
    ciphertext = encrypt_message(public_key, message)
    print(f"Texto cifrado (hex): {ciphertext.hex()}")

    # Decifração
    plaintext = decrypt_message(private_key, ciphertext)
    print(f"Texto decifrado: {plaintext}")
