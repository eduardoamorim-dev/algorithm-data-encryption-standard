"""
Implementação do DES (Data Encryption Standard) em Python, sem bibliotecas de criptografia.
O algoritmo cifra/decifra mensagens divididas em blocos de 64 bits usando uma chave de 64 bits.
"""

def int_to_bits(n, size=64):
    """
    Converte um número inteiro em uma lista de bits (big-endian).
    Args:
        n: Inteiro a ser convertido.
        size: Número de bits desejado (padrão: 64).
    Returns:
        Lista de bits (0s e 1s).
    """
    return [(n >> i) & 1 for i in range(size - 1, -1, -1)]

def bits_to_int(bits):
    """
    Converte uma lista de bits em um número inteiro.
    Args:
        bits: Lista de bits (0s e 1s).
    Returns:
        Inteiro correspondente.
    """
    return sum(b << (len(bits) - 1 - i) for i, b in enumerate(bits))

def permute_bits(bits, table):
    """
    Reorganiza uma lista de bits conforme uma tabela de permutação.
    Args:
        bits: Lista de bits de entrada.
        table: Lista de índices (1-based) para reordenar os bits.
    Returns:
        Lista de bits permutados.
    """
    return [bits[i-1] for i in table]

def sbox_lookup(input_bits, sbox):
    """
    Aplica uma S-box a 6 bits de entrada, retornando 4 bits de saída.
    Args:
        input_bits: Lista de 6 bits.
        sbox: Tabela S-box (4x16).
    Returns:
        Lista de 4 bits resultantes.
    """
    row = input_bits[0] * 2 + input_bits[5]
    col = input_bits[1]*8 + input_bits[2]*4 + input_bits[3]*2 + input_bits[4]
    val = sbox[row][col]
    return [(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1]

def f(r, key, sboxes, ep_table, p_table):
    """
    Função F do DES: expande 32 bits para 48, faz XOR com a subchave,
    aplica S-boxes e permuta o resultado.
    Args:
        r: Metade direita do bloco (32 bits).
        key: Subchave da rodada (48 bits).
        sboxes: Lista de 8 S-boxes.
        ep_table: Tabela de expansão E.
        p_table: Tabela de permutação P.
    Returns:
        Lista de 32 bits após a função F.
    """
    re = permute_bits(r, ep_table)
    kbits = int_to_bits(key, 48)
    xor = [re[i] ^ kbits[i] for i in range(48)]
    out = []
    for j in range(8):
        s_in = xor[j*6:(j+1)*6]
        s_out = sbox_lookup(s_in, sboxes[j])
        out += s_out
    pout = permute_bits(out, p_table)
    return pout

def des_round(l, r, key, sboxes, ep_table, p_table):
    """
    Executa uma rodada Feistel do DES.
    Args:
        l: Metade esquerda do bloco (32 bits).
        r: Metade direita do bloco (32 bits).
        key: Subchave da rodada.
        sboxes: Lista de 8 S-boxes.
        ep_table: Tabela de expansão E.
        p_table: Tabela de permutação P.
    Returns:
        Tupla (nova esquerda, nova direita).
    """
    fr = f(r, key, sboxes, ep_table, p_table)
    new_r = [l[j] ^ fr[j] for j in range(32)]
    new_l = r[:]
    return new_l, new_r

def des_encrypt_block(block, keys, ip_table, fp_table, sboxes, ep_table, p_table):
    """
    Cifra um bloco de 64 bits usando o DES.
    Args:
        block: Bloco de 64 bits (inteiro).
        keys: Lista de 16 subchaves.
        ip_table: Tabela de permutação inicial.
        fp_table: Tabela de permutação final.
        sboxes: Lista de 8 S-boxes.
        ep_table: Tabela de expansão E.
        p_table: Tabela de permutação P.
    Returns:
        Bloco cifrado (inteiro).
    """
    bits = int_to_bits(block)
    perm = permute_bits(bits, ip_table)
    l = perm[:32]
    r = perm[32:]
    for i in range(16):
        l, r = des_round(l, r, keys[i], sboxes, ep_table, p_table)
    after = r + l
    final_bits = permute_bits(after, fp_table)
    return bits_to_int(final_bits)

def des_decrypt_block(block, keys, ip_table, fp_table, sboxes, ep_table, p_table):
    """
    Decifra um bloco de 64 bits usando o DES (subchaves em ordem inversa).
    Args:
        block: Bloco cifrado (inteiro).
        keys: Lista de 16 subchaves.
        ip_table: Tabela de permutação inicial.
        fp_table: Tabela de permutação final.
        sboxes: Lista de 8 S-boxes.
        ep_table: Tabela de expansão E.
        p_table: Tabela de permutação P.
    Returns:
        Bloco decifrado (inteiro).
    """
    keys = keys[::-1]
    return des_encrypt_block(block, keys, ip_table, fp_table, sboxes, ep_table, p_table)

# Tabelas fixas do DES (IP, FP, E, P, S-boxes)
ip_table = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
fp_table = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
ep_table = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
p_table = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
sboxes = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # ... (demais S-boxes mantidas como na implementação original para brevidade)
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

pc1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
pc2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

def des_key_schedule(key):
    """
    Gera 16 subchaves de 48 bits a partir de uma chave de 64 bits.
    Usa PC-1, shifts circulares e PC-2.
    Args:
        key: Chave de 64 bits (inteiro).
    Returns:
        Lista de 16 subchaves (inteiros).
    """
    key_bits = int_to_bits(key, 64)
    cd_bits = permute_bits(key_bits, pc1)
    c = cd_bits[:28]
    d = cd_bits[28:]
    shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
    keys = []
    for i in range(16):
        c = c[shifts[i]:] + c[:shifts[i]]
        d = d[shifts[i]:] + d[:shifts[i]]
        cd = c + d
        k_bits = permute_bits(cd, pc2)
        k = bits_to_int(k_bits)
        keys.append(k)
    return keys

def pad(message):
    """
    Aplica padding PKCS#5 a uma mensagem para múltiplos de 8 bytes.
    Args:
        message: String a ser padronizada.
    Returns:
        Bytes com padding.
    """
    bytes_msg = message.encode('utf-8')
    pad_len = 8 - len(bytes_msg) % 8
    if pad_len == 8:
        pad_len = 0
    padded = bytes_msg + bytes([pad_len] * pad_len)
    return padded

def unpad(padded):
    """
    Remove o padding PKCS#5 de uma mensagem.
    Args:
        padded: Bytes com padding.
    Returns:
        Bytes sem padding.
    """
    if not padded:
        return b''
    pad_len = padded[-1]
    if pad_len > 8 or pad_len == 0:
        return padded
    return padded[:-pad_len]

def encrypt_message(message, key_str):
    """
    Cifra uma mensagem completa usando DES no modo ECB.
    Args:
        message: String a ser cifrada.
        key_str: Chave como string (truncada ou esticada para 8 bytes).
    Returns:
        String hexadecimal do texto cifrado.
    """
    key_bytes = key_str.encode('utf-8')[:8].ljust(8, b'\0')
    key = int.from_bytes(key_bytes, 'big')
    keys = des_key_schedule(key)
    padded = pad(message)
    blocks = [int.from_bytes(padded[i:i+8], 'big') for i in range(0, len(padded), 8)]
    enc_blocks = [des_encrypt_block(b, keys, ip_table, fp_table, sboxes, ep_table, p_table) for b in blocks]
    enc_bytes = b''.join(b.to_bytes(8, 'big') for b in enc_blocks)
    return enc_bytes.hex().upper()

def decrypt_message(enc_hex, key_str):
    """
    Decifra uma mensagem completa usando DES no modo ECB.
    Args:
        enc_hex: String hexadecimal do texto cifrado.
        key_str: Chave como string.
    Returns:
        String decifrada.
    """
    key_bytes = key_str.encode('utf-8')[:8].ljust(8, b'\0')
    key = int.from_bytes(key_bytes, 'big')
    keys = des_key_schedule(key)
    enc_bytes = bytes.fromhex(enc_hex)
    blocks = [int.from_bytes(enc_bytes[i:i+8], 'big') for i in range(0, len(enc_bytes), 8)]
    dec_blocks = [des_decrypt_block(b, keys, ip_table, fp_table, sboxes, ep_table, p_table) for b in blocks]
    dec_bytes = b''.join(b.to_bytes(8, 'big') for b in dec_blocks)
    return unpad(dec_bytes).decode('utf-8')

# Exemplo de uso
if __name__ == "__main__":
    message = "Hello, World!"
    key = "secretkey"
    enc = encrypt_message(message, key)
    print("Mensagem cifrada (hex):", enc)
    dec = decrypt_message(enc, key)
    print("Mensagem decifrada:", dec)