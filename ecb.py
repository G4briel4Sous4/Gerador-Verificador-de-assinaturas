import aes

def converter_para_decimais(text):

    bytes_lista = text.split()
    bytes_decimais = [int(byte, 16) for byte in bytes_lista]
    blocos = [bytes_decimais[i:i+16] for i in range(0, len(bytes_decimais), 16)]
    return [
        [bloco[i:i+4] for i in range(0, len(bloco), 4)]
        for bloco in blocos
    ]

def ecb_encrypt(data: str, key: bytes, rounds: int = 10):
    blocos = converter_para_decimais(data)

    blocos_cifrados = [
        aes.aes_encrypt(bloco, list(key), rounds)
        for bloco in blocos
    ]
    
    blocos_decimais = [
        [byte for byte in bloco] 
        for bloco in blocos_cifrados
    ]
    
    return blocos_decimais


def ecb_encrypt(data, key: bytes, rounds: int = 10):
    
    blocos_cifrados = [
        aes.aes_encrypt(bloco, list(key), rounds)
        for bloco in data
    ]
    
    blocos_decimais = [
        [byte for byte in bloco]  
        for bloco in blocos_cifrados
    ]
    
    return blocos_decimais

def ecb_decrypt(data: str, key: bytes, rounds: int = 10):
    
    blocos_decifrados = [
        aes.aes_decrypt(bloco, list(key), rounds)
        for bloco in data
    ]
    
    return blocos_decifrados
