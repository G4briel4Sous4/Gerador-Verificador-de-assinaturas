from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend

# Carregar a chave privada do arquivo PEM
def load_private_key(filepath):
    with open(filepath, "rb") as file:
        private_key = load_pem_private_key(file.read(), password=None, backend=default_backend())
    return private_key

# Carregar a chave pública do arquivo PEM
def load_public_key(filepath):
    with open(filepath, "rb") as file:
        public_key = load_pem_public_key(file.read(), backend=default_backend())
    return public_key

# Exibir os componentes principais
def display_key_components(private_key, public_key):
    # Extrair os componentes principais
    private_numbers = private_key.private_numbers()
    public_numbers = public_key.public_numbers()

    n_private = private_numbers.public_numbers.n  # Módulo da chave privada
    n_public = public_numbers.n  # Módulo da chave pública
    e_public = public_numbers.e  # Expoente público
    d_private = private_numbers.d  # Expoente privado

    # Exibir os componentes
    print("===== COMPONENTES DA CHAVE PRIVADA =====")
    print(f"n (módulo): {n_private}")
    print(f"d (expoente privado): {d_private}")
    print()
    print("===== COMPONENTES DA CHAVE PÚBLICA =====")
    print(f"n (módulo): {n_public}")
    print(f"e (expoente público): {e_public}")

    # Verificar se os módulos são iguais
    if n_private == n_public:
        print("\nVERIFICAÇÃO: O módulo 'n' é consistente entre as chaves pública e privada.")
    else:
        print("\nERRO: O módulo 'n' não corresponde entre as chaves pública e privada.")

if __name__ == "__main__":
    # Carregar as chaves
    private_key = load_private_key("private_key.pem")
    public_key = load_public_key("public_key.pem")

    # Exibir os componentes das chaves
    display_key_components(private_key, public_key)
