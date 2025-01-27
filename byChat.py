import gmpy2
import hashlib
from gmpy2 import mpz
import os

# Tamanho dos primos gerados
PRIME_SIZE = 1024  # Pode ser ajustado conforme necessário
E_DEFAULT_VAL = 65537  # Valor típico para o expoente público (Fermat's prime)
HASH_FUNC = hashlib.sha256  # Função de hash SHA-256

class RSA_Primes:
    def __init__(self):
        self.gen_primes()

    def gen_primes(self):
        # Função otimizada para gerar primos de tamanho PRIME_SIZE
        self.p = self.generate_prime()
        self.q = self.generate_prime()

        # Certificando-se de que p e q são diferentes
        while self.p == self.q:
            self.q = self.generate_prime()

        # Calculando n e phi(n)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)

    def generate_prime(self):
        """Gera um número primo de tamanho PRIME_SIZE bits"""
        prime = gmpy2.mpz_random(gmpy2.random_state(), PRIME_SIZE)
        while not gmpy2.is_prime(prime):
            prime = gmpy2.mpz_random(gmpy2.random_state(), PRIME_SIZE)
        return prime

    def get_prime_p(self):
        return self.p

    def get_prime_q(self):
        return self.q

    def get_n(self):
        return self.n

    def get_phi_of_n(self):
        return self.phi_n

# Continuar com o restante da implementação...


class RSA_PubKey:
    def __init__(self):
        self.exp = 0
        self.mod = 0
        self.pair_set = False

    def gen_pair(self, ppair):
        m = ppair.get_phi_of_n()
        i = E_DEFAULT_VAL
        while gmpy2.gcd(i, m) != 1:
            i += 2  # Incrementando até encontrar o primo relativo
        self.exp = i
        self.mod = ppair.get_n()
        self.pair_set = True

    def set_pair(self, exp, mod):
        if exp >= mod:
            return 1
        self.exp = exp
        self.mod = mod
        self.pair_set = True
        return 0

    def encrypt(self, message):
        if not self.pair_set or message >= self.mod:
            return 1
        return pow(message, self.exp, self.mod)

    def is_valid(self):
        return self.pair_set

class RSA_PrivKey:
    def __init__(self):
        self.exp = 0
        self.mod = 0
        self.p = 0
        self.q = 0
        self.crt_dp = 0
        self.crt_dq = 0
        self.crt_qinv = 0
        self.pair_set = False
        self.crt_set = False

    def gen_pair(self, ppair, pub_k):
        if not pub_k.is_valid():
            return 1
        e = pub_k.exp
        m = ppair.get_phi_of_n()
        self.exp = gmpy2.invert(e, m)
        self.mod = pub_k.mod
        self.pair_set = True

        p = ppair.get_prime_p()
        q = ppair.get_prime_q()

        self.crt_qinv = gmpy2.invert(q, p)
        self.crt_dp = self.exp % (p - 1)
        self.crt_dq = self.exp % (q - 1)

        self.p = p
        self.q = q
        self.crt_set = True
        return 0

    def decrypt(self, ciphertext):
        if not self.pair_set and not self.crt_set:
            return 1
        if self.crt_set:
            m1 = pow(ciphertext, self.crt_dp, self.p)
            m2 = pow(ciphertext, self.crt_dq, self.q)
            h = (self.crt_qinv * (m1 - m2)) % self.p
            m = m2 + h * self.q
        else:
            m = pow(ciphertext, self.exp, self.mod)
        return m

    def is_valid(self):
        return self.pair_set or self.crt_set

class RSA_OAEP:
    def __init__(self):
        self.pub_key = None
        self.priv_key = None
        self.m = 0
        self.cipher_set = False

    def gen_keys(self, ppair):
        self.pub_key = RSA_PubKey()
        self.pub_key.gen_pair(ppair)
        self.priv_key = RSA_PrivKey()
        self.priv_key.gen_pair(ppair, self.pub_key)

    def set_pubkey(self, pub_key):
        self.pub_key = pub_key
        self.cipher_set = False

    def set_privkey(self, priv_key):
        self.priv_key = priv_key
        self.cipher_set = False

    def encode_message(self, message):
        """Codifica a mensagem com o esquema OAEP"""
        h_len = HASH_FUNC().digest_size
        m_len = len(message)

        # Geração de um valor de padding baseado em SHA-256
        l = HASH_FUNC().digest_size
        h0 = HASH_FUNC().digest_size * b'\x00'

        # Step 1: Padding da mensagem
        l_hash = hashlib.sha256(h0 + message.encode()).digest()

        # Step 2: Gerar máscara usando a função de hash
        db = message.encode().ljust(l - 1, b'\x00')  # Mensagem preenchida com 0
        seed = os.urandom(h_len)
        db_mask = self.mask_generation_function(seed, l)
        db = bytes(x ^ y for x, y in zip(db, db_mask))

        seed_mask = self.mask_generation_function(db, h_len)
        seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

        return db + seed

    def mask_generation_function(self, input_data, length):
        """Geração de máscara baseada em função de hash"""
        h = HASH_FUNC()
        mask = b''
        counter = 0
        while len(mask) < length:
            h.update(input_data + counter.to_bytes(4, byteorder='big'))
            mask += h.digest()
            counter += 1
        return mask[:length]

    def encrypt(self, message):
        """Encripta a mensagem com a chave pública"""
        encoded_msg = self.encode_message(message)
        message_int = int.from_bytes(encoded_msg, byteorder='big')
        ciphertext = self.pub_key.encrypt(message_int)
        return ciphertext

    def decrypt(self, ciphertext):
        """Desencripta a mensagem com a chave privada"""
        decrypted_int = self.priv_key.decrypt(ciphertext)
        decrypted_msg = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')

        # A partir daqui, o passo de verificação é necessário
        return decrypted_msg.rstrip(b'\x00').decode('utf-8')

# Exemplo de uso
ppair = RSA_Primes()
rsa_oaep = RSA_OAEP()
rsa_oaep.gen_keys(ppair)

# Mensagem
message = "Texto secreto"
print(f"Original Message: {message}")

# Encriptação
ciphertext = rsa_oaep.encrypt(message)
print(f"Ciphertext: {ciphertext}")

# Desencriptação
decrypted_message = rsa_oaep.decrypt(ciphertext)
print(f"Decrypted Message: {decrypted_message}")
