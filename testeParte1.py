from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Geração de chaves RSA usando a biblioteca
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024  # Tamanho da chave deve coincidir com o seu código real
    )
    public_key = private_key.public_key()
    return public_key, private_key

# Cifração usando a chave pública
def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Decifração usando a chave privada
def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Teste
if __name__ == "__main__":
    # Mensagem original
    message = b'Mensagem de teste para RSA com OAEP'
    print("Mensagem original:", message)

    # Gerar chaves
    public_key, private_key = generate_keys()

    # Cifrar a mensagem
    ciphertext = encrypt_message(public_key, message)
    print("Mensagem cifrada:", ciphertext)

    # Decifrar a mensagem
    decrypted_message = decrypt_message(private_key, ciphertext)
    print("Mensagem decifrada:", decrypted_message)

    # Validar se a mensagem decifrada é igual à original
    assert decrypted_message == message, "Erro: a mensagem decifrada não coincide com a original!"
    print("Teste bem-sucedido: a mensagem original foi recuperada com sucesso!")
