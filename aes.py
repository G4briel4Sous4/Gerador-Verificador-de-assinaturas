# Tabela oficial da S-Box AES 16x16 (para cifragem)
S_BOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

INV_S_BOX = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
]

def format_state_hex(text):
    """Formata o estado como uma matriz 4x4 de valores hexadecimais."""
    return ' '.join(' '.join(f"{byte:02x}" for byte in row) for row in text)

def print_state(state, label):
    """Imprime o estado formatado."""
    print(f"\n{label}:")
    for row in state:
        print(" ".join(f"{byte:02X}" for byte in row))




# CIPHER     



def add_round_key(state, round_key):
    """Realiza a operação AddRoundKey com matrizes 4x4."""
    temp = state

    for i in range(4):
        for j in range(4):
            temp[i][j] ^= round_key[i][j]

    return temp

def sub_bytes(state):
    """Aplica substituição de bytes usando a S-Box."""

    temp = state

    for i in range(4):
        for j in range(4):
            byte = temp[i][j]
            row = (byte >> 4) & 0x0F
            col = byte & 0x0F
            temp[i][j] = S_BOX[row][col]
    
    return temp

def shift_rows(state):
    """Realiza a operação ShiftRows respeitando a representação coluna por coluna."""
    # Linha 1: Desloca 1 posição à esquerda
    temp  = state

    temp[0][1], temp[1][1], temp[2][1], temp[3][1] = (
        temp[1][1], temp[2][1], temp[3][1], temp[0][1]
    )

    # Linha 2: Desloca 2 posições à esquerda
    temp[0][2], temp[1][2], temp[2][2], temp[3][2] = (
        temp[2][2], temp[3][2], temp[0][2], temp[1][2]
    )

    # Linha 3: Desloca 3 posições à esquerda
    temp[0][3], temp[1][3], temp[2][3], temp[3][3] = (
        temp[3][3], temp[0][3], temp[1][3], temp[2][3]
    )

    return temp

# Função para multiplicação por 2 em GF(2^8)
def xtime(x):
    return ((x << 1) & 0xFF) ^ (0x1B if (x & 0x80) else 0)

# Função para multiplicação por 3 em GF(2^8)
def mul3(x):
    return xtime(x) ^ x

# Função de MixColumns
def mix_columns(state):

    temp = state
    # Matriz de transformação fixa para MixColumns
    mix_matrix = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]
    
    # Matriz temporária para armazenar o resultado
    temp_state = [[0] * 4 for _ in range(4)]
    
    # Multiplica e aplica o XOR para cada coluna
    for i in range(4):
        for j in range(4):
            temp_state[i][j] = 0
            for k in range(4):
                if mix_matrix[j][k] == 0x01:
                    temp_state[i][j] ^= temp[i][k]
                elif mix_matrix[j][k] == 0x02:
                    temp_state[i][j] ^= xtime(temp[i][k])
                elif mix_matrix[j][k] == 0x03:
                    temp_state[i][j] ^= mul3(temp[i][k])
    
    # Atualiza o estado com o resultado da operação de MixColumns
    for i in range(4):
        for j in range(4):
            temp[i][j] = temp_state[i][j]
            
    return temp

def key_expansion(key, rounds):

    rounds = int(rounds)  # Garante que rounds seja um inteiro
    """Expande a chave para o número especificado de rodadas."""
    # Constantes para AES
    Nb = 4  # Número de colunas (32 bits) no estado
    Nk = 4  # Número de palavras (32 bits) na chave original
    Nr = rounds  # Número de rodadas (passado como argumento)
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    # Conversão da chave inicial em palavras (w[0] até w[Nk-1])
    w = []
    for i in range(Nk):
        w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    # Expansão da chave para (Nr + 1) * Nb palavras
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]  # Última palavra gerada

        # RotWord e SubWord a cada Nk palavras
        if i % Nk == 0:
            # RotWord (circular shift)
            temp = temp[1:] + temp[:1]
            # SubWord (substituição via S-Box)
            temp = [S_BOX[b >> 4][b & 0x0F] for b in temp]
            # XOR com RCON
            temp[0] ^= RCON[(i // Nk) - 1]

        # SubWord para o caso especial de AES-192 ou AES-256 (Nk > 6)
        elif Nk > 6 and i % Nk == 4:
            temp = [S_BOX[b >> 4][b & 0x0F] for b in temp]

        # XOR com a palavra Nk posições antes
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    # Retorna as chaves expandidas em blocos de 4 palavras (4x4 bytes)
    return [w[i:i + Nb] for i in range(0, len(w), Nb)]


def aes_encrypt(text, key, rounds):

    rounds = int(rounds)

    state = text

    firstAddRoundKey = 0
    afterSubBytes = 0
    afterShiftRows = 0
    afterMixColumns = 0
    afterAddRoundKey = 0

    round_keys = key_expansion(key, rounds)  # Corrige o formato das subchaves

    # Rodada inicial
    firstAddRoundKey = add_round_key(state, round_keys[0])

    # Rodadas intermediárias
    if rounds == 1:
        # print(f"round[0].start: {format_state_hex(firstAddRoundKey)}")
        afterSubBytes = sub_bytes(firstAddRoundKey)
        # print(f"round[0].sub_bytes: {format_state_hex(afterSubBytes)}")
        afterShiftRows = shift_rows(afterSubBytes)
        # print(f"round[0].shift_rows: {format_state_hex(afterShiftRows)}")
        afterAddRoundKey = add_round_key(afterShiftRows, round_keys[1])
        # print(f"round[0].add_round_keys: {format_state_hex(afterAddRoundKey)}")
    else: 
        for i in range(1, rounds):
            # print(f"round[{i}].start: {format_state_hex(firstAddRoundKey)}")
            afterSubBytes = sub_bytes(firstAddRoundKey)
            # print(f"round[{i}].sub_bytes: {format_state_hex(afterSubBytes)}")
            afterShiftRows = shift_rows(afterSubBytes)
            # print(f"round[{i}].shift_rows: {format_state_hex(afterShiftRows)}")
            afterMixColumns = mix_columns(afterShiftRows)
            # print(f"round[{i}].mix_columns: {format_state_hex(afterMixColumns)}")
            afterAddRoundKey = add_round_key(afterMixColumns, round_keys[i])
            # print(f"round[{i}].add_round_keys: {format_state_hex(afterAddRoundKey)}")
            # print(f"State {i}", state)

        # Última rodada
        # print(f"round[{rounds}].start: {format_state_hex(afterAddRoundKey)}")
        afterSubBytes = sub_bytes(afterAddRoundKey)
        # print(f"round[{rounds}].sub_bytes: {format_state_hex(afterSubBytes)}")
        afterShiftRows = shift_rows(afterSubBytes)
        # print(f"round[{rounds}].shift_rows: {format_state_hex(afterShiftRows)}")
        afterAddRoundKey = add_round_key(afterShiftRows, round_keys[rounds])
        # print(f"round[{rounds}].add_round_keys: {format_state_hex(afterAddRoundKey)}")
        # print("Last State ", format_state_hex(afterAddRoundKey))

    return state





# DECIPHER





def inv_add_round_key(state, round_key):
    """Realiza a operação AddRoundKey inversa (também XOR com a chave)."""

    temp = state

    for i in range(4):
        for j in range(4):
            temp[i][j] ^= round_key[i][j]
    
    return temp

def inv_sub_bytes(state):
    """
    Aplica a substituição de bytes inversa usando a tabela INV_S_BOX.
    `state` deve ser uma matriz 4x4 de bytes (inteiros de 0 a 255).
    """
    # Cria uma cópia profunda para evitar modificar o estado original.
    temp = [row[:] for row in state]

    for i in range(4):
        for j in range(4):
            byte = temp[i][j]
            row = (byte >> 4) & 0x0F  # Obtém os 4 bits mais significativos
            col = byte & 0x0F         # Obtém os 4 bits menos significativos
            temp[i][j] = INV_S_BOX[row][col]  # Substitui usando INV_S_BOX

    return temp


def inv_shift_rows(state):
    """Realiza a operação ShiftRows respeitando a representação coluna por coluna."""
    # Linha 1: Desloca 1 posição à esquerda
    temp  = state

    temp[0][1], temp[1][1], temp[2][1], temp[3][1] = (
        temp[3][1], temp[0][1], temp[1][1], temp[2][1]
    )

    # Linha 2: Desloca 2 posições à direita
    temp[0][2], temp[1][2], temp[2][2], temp[3][2] = (
        temp[2][2], temp[3][2], temp[0][2], temp[1][2]
    )

    # Linha 3: Desloca 3 posições à direita
    temp[0][3], temp[1][3], temp[2][3], temp[3][3] = (
        temp[1][3], temp[2][3], temp[3][3], temp[0][3]
    )

    return temp

# Função para transpor a matriz (linhas <-> colunas)
def transpose(matrix):
    """
    Transpõe uma matriz 4x4.
    Exemplo: de linhas para colunas ou vice-versa.
    """
    return [[matrix[row][col] for row in range(4)] for col in range(4)]

# Função para multiplicação no campo GF(2^8)
def galois_multiply(a, b):
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

# Matriz inversa do MixColumns no AES
INV_MIX_COLUMNS_MATRIX = [
    [0x0E, 0x0B, 0x0D, 0x09],
    [0x09, 0x0E, 0x0B, 0x0D],
    [0x0D, 0x09, 0x0E, 0x0B],
    [0x0B, 0x0D, 0x09, 0x0E],
]

# Função InvMixColumns 
def inv_mix_columns(state):
    """
    Aplica a operação InvMixColumns em uma matriz state (4x4) organizada por colunas.
    """
    new_state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            value = 0
            for k in range(4):
                value ^= galois_multiply(INV_MIX_COLUMNS_MATRIX[row][k], state[k][col])
            new_state[row][col] = value
    return new_state

# Função principal que organiza a entrada, aplica InvMixColumns e reorganiza a saída
def process_inv_mix_columns(input_state):
    # Transpõe a matriz de linhas para colunas
    transposed_input = transpose(input_state)

    # Aplica InvMixColumns
    result = inv_mix_columns(transposed_input)

    # Transpõe a matriz de volta para o formato original (colunas -> linhas)
    final_result = transpose(result)

    return final_result


# Reformatar entrada e saída
def format_input_output(input_bytes, to_columns=True):
    if to_columns:  # Converter bytes em formato col-major para matriz 4x4
        return [[input_bytes[i + 4 * j] for i in range(4)] for j in range(4)]
    else:  # Converter matriz 4x4 de volta para formato col-major
        return [input_bytes[row][col] for col in range(4) for row in range(4)]

def inv_key_expansion(key, rounds):
    rounds = int(rounds)
    """Expande a chave para o número especificado de rodadas e inverte a ordem das chaves."""
    
    # Constantes para AES
    Nb = 4  # Número de colunas (32 bits) no estado
    Nk = 4  # Número de palavras (32 bits) na chave original
    Nr = rounds  # Número de rodadas (passado como argumento)
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    # Conversão da chave inicial em palavras (w[0] até w[Nk-1])
    w = []
    for i in range(Nk):
        w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    # Expansão da chave para (Nr + 1) * Nb palavras
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]  # Última palavra gerada

        # RotWord e SubWord a cada Nk palavras
        if i % Nk == 0:
            # RotWord (circular shift)
            temp = temp[1:] + temp[:1]
            # SubWord (substituição via S-Box)
            temp = [S_BOX[b >> 4][b & 0x0F] for b in temp]
            # XOR com RCON
            temp[0] ^= RCON[(i // Nk) - 1]

        # SubWord para o caso especial de AES-192 ou AES-256 (Nk > 6)
        elif Nk > 6 and i % Nk == 4:
            temp = [S_BOX[b >> 4][b & 0x0F] for b in temp]

        # XOR com a palavra Nk posições antes
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    # Agrupa as chaves expandidas em blocos de 4 palavras (4x4 bytes)
    expanded_keys = [w[i:i + Nb] for i in range(0, len(w), Nb)]

    # Retorna as chaves na ordem inversa
    return expanded_keys[::-1]


def aes_decrypt(ciphertext, key, rounds):

    rounds = int(rounds)
    """Descriptografa o texto cifrado usando a chave fornecida."""
    round_keys = inv_key_expansion(key, rounds)

    # for i, rk in enumerate(round_keys):
    #     print(f"Round Key {i}:", format_state_hex(rk))

    state = ciphertext

    # Etapa inicial: Adiciona a chave da última rodada
    state = inv_add_round_key(state, round_keys[0])

    # Rodadas principais (Nr-1 rodadas)
    for round in range(1, rounds):
        # print(f"round[{round}].start: {format_state_hex(state)}")
        state = inv_shift_rows(state)
        # print(f"round[{round}].inv.shift_rows: {format_state_hex(state)}")
        state = inv_sub_bytes(state)
        # print(f"round[{round}].inv.sub_bytes: {format_state_hex(state)}")
        state = inv_add_round_key(state, round_keys[round])
        # print(f"round[{round}].inv.add_round_keys: {format_state_hex(state)}")
        state = process_inv_mix_columns(state)
        # print(f"round[{round}].inv.mix.columns: {format_state_hex(state)}")

    # Rodada final (sem InvMixColumns)
    state = inv_shift_rows(state)
    # print("Final round.inv.shift_rows: ", format_state_hex(state))
    state = inv_sub_bytes(state)
    # print("Final round.inv.sub_bytes: ", format_state_hex(state))
    state = inv_add_round_key(state, round_keys[rounds])
    # print("Final round.inv.add_round_keys: ", format_state_hex(state))

    return state





import re

def verificar_formato(text):
    # Verificar se a entrada contém exatamente 16 bytes
    bytes_lista = text.split()
    if len(bytes_lista) != 16:
        return False

    # Verificar se cada byte é um valor hexadecimal válido de 2 caracteres
    for byte in bytes_lista:
        if not re.match(r'^[0-9a-fA-F]{2}$', byte):
            return False
    
    return True

def converter_para_bytes(matriz_hex):

    # Cria uma lista para armazenar os valores inteiros
    lista_bytes = []

    # Divide a string de entrada em valores hexadecimais, ignorando espaços extras
    valores_hex = matriz_hex.split()

    # Itera sobre os valores hexadecimais e converte para inteiros
    for item in valores_hex:
        lista_bytes.append(int(item, 16))
    
    # Cria e retorna o objeto de bytes
    return bytes(lista_bytes)

def converter_para_decimais(text):
    # Passo 1: Remover espaços extras e dividir a string em uma lista de bytes
    bytes_lista = text.split()
    
    # Passo 2: Converter os bytes de hexadecimal para decimal
    bytes_decimais = [int(byte, 16) for byte in bytes_lista]
    
    # Passo 3: Organizar os bytes em uma lista de listas de 4 bytes
    matriz = [bytes_decimais[i:i+4] for i in range(0, len(bytes_decimais), 4)]
    
    return matriz

# def main():
    
#     choice = input("Digite 1 para cifrar e 2 para decifrar: ")

#     if choice == '1':
#         rodadas = input("\nQuantas rodadas deseja? ")
#         textCipher = input("\nDigite 16 bytes da seguinte maneira: \n"
#                      "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff\n"
#                      "Insira aqui: ")
        
#         if verificar_formato(textCipher) == False:
#             print("\nFormato inválido! Digite 16 bytes separados por um espaço.")
#             return 
        
#         resultadoText = converter_para_decimais(textCipher)
#         print("\nTexto: ", resultadoText)
#         chaveCipher = input("\nAgora digite a chave no mesmo formato:\n"
#                       "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n"
#                       "Insira aqui: ")
        
#         if verificar_formato(chaveCipher) == False:
#             print("\nFormato inválido! Digite 16 bytes separados por um espaço.")
#             return 

#         resultadoChave = converter_para_bytes(chaveCipher)
#         print("\nChave: ", resultadoChave)

#         print("Resultado text: ", resultadoText)
#         print("Resultado chave: ", resultadoChave)
#         print("Rodadas: ", rodadas)

#         encrypted_state = aes_encrypt(resultadoText, resultadoChave, rodadas)

#         print("\nTexto Cifrado: ", format_state_hex(encrypted_state))

#     elif choice == '2':
#         rodadas = input("\nQuantas rodadas deseja? ")
#         textDecipher = input("\nDigite 16 bytes da seguinte maneira: \n"
#                      "69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a\n"
#                      "Insira aqui: ")
        
#         if verificar_formato(textDecipher) == False:
#             print("\nFormato inválido! Digite 16 bytes separados por um espaço.")
#             return 

#         resultadoTextDecipher = converter_para_decimais(textDecipher)
#         print("\nTexto para decifrar: ", resultadoTextDecipher)
#         chaveDecipher = input("\nAgora digite a chave no mesmo formato:\n"
#                       "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n"
#                       "Insira aqui: ")
        
#         if verificar_formato(chaveDecipher) == False:
#             print("\nFormato inválido! Digite 16 bytes separados por um espaço.")
#             return 

#         resultadoChave = converter_para_bytes(chaveDecipher)
#         print("\nChave: ", resultadoChave)
#         decrypted_state = aes_decrypt(resultadoTextDecipher, resultadoChave, rodadas)
        
#         print("\nTexto Decifrado: ", format_state_hex(decrypted_state))
    
#     else:
#         print("\nOpção inválida :(")

# if __name__ == "__main__":
#     main()
