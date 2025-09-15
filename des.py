"""
Implementação do DES (Data Encryption Standard) em Python com sistema de logging detalhado.
O algoritmo cifra/decifra mensagens divididas em blocos de 64 bits usando uma chave de 64 bits.
"""

import logging
from typing import List, Optional

class DESLogger:
    """Sistema de logging personalizado para o DES"""
    
    def __init__(self, level=logging.INFO):
        self.logger = logging.getLogger('DES')
        self.logger.setLevel(level)
        
        # Remove handlers existentes para evitar duplicação
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Configura handler para console
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def info(self, message):
        self.logger.info(message)
    
    def debug(self, message):
        self.logger.debug(message)
    
    def step(self, message):
        """Log para passos importantes"""
        self.logger.info(f"[PASSO] {message}")
    
    def bits_info(self, name, bits, show_bits=True):
        """Log formatado para informações de bits"""
        if isinstance(bits, list) and len(bits) > 0:
            if show_bits and len(bits) <= 64:
                bits_str = ''.join(map(str, bits))
                self.logger.info(f"{name}: {bits_str} (tamanho: {len(bits)} bits)")
            else:
                self.logger.info(f"{name}: tamanho {len(bits)} bits")
        else:
            self.logger.info(f"{name}: {bits}")

# Instância global do logger
des_logger = DESLogger()

def int_to_bits(n, size=64):
    """
    Converte um número inteiro em uma lista de bits (big-endian).
    """
    bits = [(n >> i) & 1 for i in range(size - 1, -1, -1)]
    des_logger.debug(f"Convertendo {n} para {size} bits")
    return bits

def bits_to_int(bits):
    """
    Converte uma lista de bits em um número inteiro.
    """
    result = sum(b << (len(bits) - 1 - i) for i, b in enumerate(bits))
    des_logger.debug(f"Convertendo {len(bits)} bits para inteiro: {result}")
    return result

def permute_bits(bits, table):
    """
    Reorganiza uma lista de bits conforme uma tabela de permutação.
    """
    result = [bits[i-1] for i in table]
    des_logger.debug(f"Permutação aplicada: {len(bits)} → {len(result)} bits")
    return result

def sbox_lookup(input_bits, sbox):
    """
    Aplica uma S-box a 6 bits de entrada, retornando 4 bits de saída.
    """
    row = input_bits[0] * 2 + input_bits[5]
    col = input_bits[1]*8 + input_bits[2]*4 + input_bits[3]*2 + input_bits[4]
    val = sbox[row][col]
    result = [(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1]
    
    input_str = ''.join(map(str, input_bits))
    output_str = ''.join(map(str, result))
    des_logger.debug(f"S-box: {input_str} → {output_str} (linha={row}, col={col}, val={val})")
    
    return result

def f(r, key, sboxes, ep_table, p_table):
    """
    Função F do DES: expande 32 bits para 48, faz XOR com a subchave,
    aplica S-boxes e permuta o resultado.
    """
    des_logger.step("Iniciando função F")
    
    # Expansão
    re = permute_bits(r, ep_table)
    des_logger.bits_info("R expandido (E)", re, show_bits=False)
    
    # XOR com subchave
    kbits = int_to_bits(key, 48)
    xor = [re[i] ^ kbits[i] for i in range(48)]
    des_logger.bits_info("Subchave K", kbits, show_bits=False)
    des_logger.bits_info("E(R) ⊕ K", xor, show_bits=False)
    
    # S-boxes
    des_logger.debug("Aplicando S-boxes:")
    out = []
    for j in range(8):
        s_in = xor[j*6:(j+1)*6]
        s_out = sbox_lookup(s_in, sboxes[j])
        out += s_out
        des_logger.debug(f"  S{j+1}: {''.join(map(str, s_in))} → {''.join(map(str, s_out))}")
    
    des_logger.bits_info("Saída das S-boxes", out)
    
    # Permutação P
    pout = permute_bits(out, p_table)
    des_logger.bits_info("f(R,K) após permutação P", pout)
    
    return pout

def des_round(l, r, key, sboxes, ep_table, p_table, round_num):
    """
    Executa uma rodada Feistel do DES.
    """
    des_logger.step(f"RODADA {round_num}")
    des_logger.bits_info("L inicial", l)
    des_logger.bits_info("R inicial", r)
    des_logger.info(f"Subchave K{round_num}: {hex(key)}")
    
    # Função F
    fr = f(r, key, sboxes, ep_table, p_table)
    
    # XOR L com f(R,K)
    new_r = [l[j] ^ fr[j] for j in range(32)]
    new_l = r[:]
    
    des_logger.bits_info("L ⊕ f(R,K) = nova R", new_r)
    des_logger.bits_info("Nova L (antiga R)", new_l)
    des_logger.info(f"Fim da rodada {round_num}")
    des_logger.info("-" * 50)
    
    return new_l, new_r

def des_encrypt_block(block, keys, ip_table, fp_table, sboxes, ep_table, p_table):
    """
    Cifra um bloco de 64 bits usando o DES.
    """
    des_logger.step("INICIANDO CIFRAGEM DO BLOCO")
    des_logger.info(f"Bloco de entrada: {hex(block)} ({block})")
    
    # Permutação inicial
    bits = int_to_bits(block)
    des_logger.bits_info("Bloco em bits", bits)
    
    perm = permute_bits(bits, ip_table)
    des_logger.bits_info("Após permutação inicial (IP)", perm)
    
    l = perm[:32]
    r = perm[32:]
    des_logger.bits_info("L0 (metade esquerda)", l)
    des_logger.bits_info("R0 (metade direita)", r)

    # 16 rodadas
    for i in range(16):
        l, r = des_round(l, r, keys[i], sboxes, ep_table, p_table, i+1)
    
    # Troca final e permutação final
    des_logger.step("FINALIZANDO CIFRAGEM")
    after = r + l  # Troca L16 e R16
    des_logger.bits_info("Após troca final (R16||L16)", after)
    
    final_bits = permute_bits(after, fp_table)
    des_logger.bits_info("Após permutação final (FP)", final_bits)
    
    result = bits_to_int(final_bits)
    des_logger.info(f"Bloco cifrado: {hex(result)} ({result})")
    des_logger.info("=" * 60)
    
    return result

def des_decrypt_block(block, keys, ip_table, fp_table, sboxes, ep_table, p_table):
    """
    Decifra um bloco de 64 bits usando o DES (subchaves em ordem inversa).
    """
    des_logger.step("INICIANDO DECIFRAGEM DO BLOCO")
    keys = keys[::-1]  # Inverte a ordem das subchaves
    des_logger.info("Usando subchaves em ordem inversa para decifragem")
    return des_encrypt_block(block, keys, ip_table, fp_table, sboxes, ep_table, p_table)

# Tabelas fixas do DES
ip_table = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
fp_table = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
ep_table = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
p_table = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
sboxes = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
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
    """
    des_logger.step("GERAÇÃO DAS SUBCHAVES")
    des_logger.info(f"Chave principal: {hex(key)} ({key})")
    
    key_bits = int_to_bits(key, 64)
    des_logger.bits_info("Chave em bits", key_bits)
    
    # PC-1: Remove bits de paridade e reorganiza
    cd_bits = permute_bits(key_bits, pc1)
    des_logger.bits_info("Após PC-1", cd_bits, show_bits=False)
    
    c = cd_bits[:28]
    d = cd_bits[28:]
    des_logger.bits_info("C0 (metade esquerda)", c, show_bits=False)
    des_logger.bits_info("D0 (metade direita)", d, show_bits=False)
    
    shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
    keys = []
    
    for i in range(16):
        # Shift circular
        c = c[shifts[i]:] + c[:shifts[i]]
        d = d[shifts[i]:] + d[:shifts[i]]
        
        des_logger.debug(f"Rodada {i+1}: shift de {shifts[i]} posições")
        
        # Concatena C e D
        cd = c + d
        
        # PC-2: Reduz de 56 para 48 bits
        k_bits = permute_bits(cd, pc2)
        k = bits_to_int(k_bits)
        keys.append(k)
        
        des_logger.info(f"K{i+1}: {hex(k)}")
    
    des_logger.info("Geração de subchaves concluída")
    des_logger.info("=" * 60)
    return keys

def pad(message):
    """
    Aplica padding PKCS#5 a uma mensagem para múltiplos de 8 bytes.
    """
    bytes_msg = message.encode('utf-8')
    pad_len = 8 - len(bytes_msg) % 8
    if pad_len == 8:
        pad_len = 0
    padded = bytes_msg + bytes([pad_len] * pad_len)
    
    des_logger.info(f"Padding aplicado: {len(bytes_msg)} → {len(padded)} bytes")
    des_logger.debug(f"Mensagem original: {bytes_msg}")
    des_logger.debug(f"Mensagem com padding: {padded}")
    
    return padded

def unpad(padded):
    """
    Remove o padding PKCS#5 de uma mensagem.
    """
    if not padded:
        return b''
    
    pad_len = padded[-1]
    if pad_len > 8 or pad_len == 0:
        des_logger.debug("Padding inválido detectado")
        return padded
    
    result = padded[:-pad_len]
    des_logger.info(f"Padding removido: {len(padded)} → {len(result)} bytes")
    return result

def encrypt_message(message, key_str, verbose=True):
    """
    Cifra uma mensagem completa usando DES no modo ECB.
    """
    if verbose:
        des_logger.step("INICIANDO CIFRAGEM DA MENSAGEM")
        des_logger.info(f"Mensagem: '{message}'")
        des_logger.info(f"Chave: '{key_str}'")
    
    # Prepara a chave
    key_bytes = key_str.encode('utf-8')[:8].ljust(8, b'\0')
    key = int.from_bytes(key_bytes, 'big')
    
    if verbose:
        des_logger.info(f"Chave processada: {key_bytes} → {hex(key)}")
    
    # Gera subchaves
    keys = des_key_schedule(key)
    
    # Aplica padding e divide em blocos
    padded = pad(message)
    blocks = [int.from_bytes(padded[i:i+8], 'big') for i in range(0, len(padded), 8)]
    
    if verbose:
        des_logger.info(f"Número de blocos a cifrar: {len(blocks)}")
    
    # Cifra cada bloco
    enc_blocks = []
    for i, block in enumerate(blocks):
        if verbose:
            des_logger.step(f"CIFRANDO BLOCO {i+1}/{len(blocks)}")
        enc_block = des_encrypt_block(block, keys, ip_table, fp_table, sboxes, ep_table, p_table)
        enc_blocks.append(enc_block)
    
    # Converte para hexadecimal
    enc_bytes = b''.join(b.to_bytes(8, 'big') for b in enc_blocks)
    result = enc_bytes.hex().upper()
    
    if verbose:
        des_logger.step("CIFRAGEM CONCLUÍDA")
        des_logger.info(f"Resultado final: {result}")
        des_logger.info("=" * 80)
    
    return result

def decrypt_message(enc_hex, key_str, verbose=True):
    """
    Decifra uma mensagem completa usando DES no modo ECB.
    """
    if verbose:
        des_logger.step("INICIANDO DECIFRAGEM DA MENSAGEM")
        des_logger.info(f"Texto cifrado (hex): {enc_hex}")
        des_logger.info(f"Chave: '{key_str}'")
    
    # Prepara a chave
    key_bytes = key_str.encode('utf-8')[:8].ljust(8, b'\0')
    key = int.from_bytes(key_bytes, 'big')
    keys = des_key_schedule(key)
    
    # Converte de hexadecimal e divide em blocos
    enc_bytes = bytes.fromhex(enc_hex)
    blocks = [int.from_bytes(enc_bytes[i:i+8], 'big') for i in range(0, len(enc_bytes), 8)]
    
    if verbose:
        des_logger.info(f"Número de blocos a decifrar: {len(blocks)}")
    
    # Decifra cada bloco
    dec_blocks = []
    for i, block in enumerate(blocks):
        if verbose:
            des_logger.step(f"DECIFRANDO BLOCO {i+1}/{len(blocks)}")
        dec_block = des_decrypt_block(block, keys, ip_table, fp_table, sboxes, ep_table, p_table)
        dec_blocks.append(dec_block)
    
    # Remove padding e decodifica
    dec_bytes = b''.join(b.to_bytes(8, 'big') for b in dec_blocks)
    result = unpad(dec_bytes).decode('utf-8')
    
    if verbose:
        des_logger.step("DECIFRAGEM CONCLUÍDA")
        des_logger.info(f"Mensagem decifrada: '{result}'")
        des_logger.info("=" * 80)
    
    return result

def set_log_level(level):
    """
    Define o nível de logging.
    Níveis: DEBUG (mais detalhado), INFO (padrão), WARNING, ERROR
    """
    des_logger.logger.setLevel(level)

if __name__ == "__main__":
    # Pode ajustar o nível de logging conforme necessário
    # set_log_level(logging.DEBUG)  # Para ver todos os detalhes
    
    message = "Hello, World!"
    key = "secretkey"
    
    print("=== DEMONSTRAÇÃO DO DES COM LOGGING ===\n")
    
    # Cifragem
    enc = encrypt_message(message, key)
    print(f"\nMensagem cifrada (hex): {enc}")
    
    print("\n" + "="*80 + "\n")
    
    # Decifragem
    dec = decrypt_message(enc, key)
    print(f"\nMensagem decifrada: {dec}")
    
    print("\n" + "="*80)
    print("=== EXEMPLO COM LOGGING REDUZIDO ===\n")
    set_log_level(logging.WARNING)
    
    enc2 = encrypt_message("Teste sem muito log", key, verbose=False)
    dec2 = decrypt_message(enc2, key, verbose=False)
    
    print(f"Cifrado: {enc2}")
    print(f"Decifrado: {dec2}")