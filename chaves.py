import random
from math import gcd
from hashlib import sha256

# Função Miller-Rabin para testar a primalidade
def miller_rabin(n, k=40):
    """ Teste de Miller-Rabin para primalidade de n, executado k vezes. """
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=1024):
    """Gera um número primo com exatamente 'bits' bits usando o teste de Miller-Rabin."""
    while True:
        num = random.getrandbits(bits) | (1 << (bits - 1)) | 1  # Garantir o bit mais significativo e ímpar
        if miller_rabin(num):
            return num


# Função para calcular o inverso multiplicativo de e módulo φ(n)
def mod_inverse(a, m):
    """ Retorna o inverso multiplicativo de a mod m utilizando o algoritmo de Euclides estendido. """
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_rsa_keys(bits=1024):
    """Gera as chaves pública e privada RSA com um módulo n de exatamente 'bits' bits."""
    prime_bits = bits // 2
    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)
        n = p * q
        if n.bit_length() == bits:  # Verificar se n tem exatamente 'bits' bits
            break
    
    phi_n = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)
    d = mod_inverse(e, phi_n)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key


# Função para testar a geração de chaves
# def test_rsa_key_generation():
#     public_key, private_key = generate_rsa_keys(bits=1024)
#     print("Chave Pública: (e, n)")
#     print("e:", public_key[0])
#     print("n:", public_key[1])
#     print("\nChave Privada: (d, n)")
#     print("d:", private_key[0])
#     print("n:", private_key[1])

# # Executando o teste para gerar as chaves RSA
# test_rsa_key_generation()
