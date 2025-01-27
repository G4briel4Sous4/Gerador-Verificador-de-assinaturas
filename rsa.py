import random
from math import gcd
from chaves import miller_rabin, generate_prime, mod_inverse, generate_rsa_keys

# Função de cifração RSA
def rsa_encrypt(plaintext, public_key):
    """ Cifra a mensagem utilizando a chave pública """
    e, n = public_key
    # Convertendo o texto em um número inteiro
    plaintext_int = int.from_bytes(plaintext.encode(), 'big')
    # Cifrar utilizando a fórmula C = P^e % n
    ciphertext_int = pow(plaintext_int, e, n)
    return ciphertext_int

# Função de decifração RSA
def rsa_decrypt(ciphertext, private_key):
    """ Decifra a mensagem utilizando a chave privada """
    d, n = private_key
    # Decifrar utilizando a fórmula P = C^d % n
    plaintext_int = pow(ciphertext, d, n)
    # Convertendo o número inteiro de volta para texto
    plaintext = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big').decode()
    return plaintext

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
    message = "Mensagem muuuito secreta"
    print("\nMensagem original:", message)
    
    # Cifração
    ciphertext = rsa_encrypt(message, public_key)
    print("Mensagem cifrada:", ciphertext)
    
    # Decifração
    decrypted_message = rsa_decrypt(ciphertext, private_key)
    print("Mensagem decifrada:", decrypted_message)

# Executando o teste para geração de chaves e cifração/decifração
test_rsa_encryption()
