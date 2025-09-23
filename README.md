# DES (Data Encryption Standard) - Python Implementation

Uma implementação completa do algoritmo DES em Python puro, sem dependências externas, com sistema de logging detalhado para fins educacionais.

## Características

- **Implementação pura em Python** - Sem bibliotecas de criptografia
- **Sistema de logging completo** - Visualize cada passo do algoritmo
- **Conformidade com o padrão DES** - Todas as tabelas e operações oficiais
- **Modo ECB** - Cifragem/decifragem de mensagens de qualquer tamanho
- **Padding PKCS#5** - Tratamento automático de blocos incompletos

## Uso Rápido

```python
from des_implementation import encrypt_message, decrypt_message

# Cifrar mensagem
mensagem = "Hello, World!"
chave = "secretkey"
cifrado = encrypt_message(mensagem, chave)
print(f"Cifrado: {cifrado}")

# Decifrar mensagem
decifrado = decrypt_message(cifrado, chave)
print(f"Decifrado: {decifrado}")
```

## Sistema de Logging

O sistema de logging mostra cada etapa do processo:

```python
from des_implementation import set_log_level
import logging

# Logging completo (padrão)
encrypt_message("Hello", "key")

# Apenas erros e avisos
set_log_level(logging.WARNING)

# Debug completo (mostra bits e operações internas)
set_log_level(logging.DEBUG)
```

### Exemplo de saída do logging:
```
[PASSO] INICIANDO CIFRAGEM DA MENSAGEM
INFO - Mensagem: 'Hello, World!'
INFO - Chave: 'secretkey'
[PASSO] GERAÇÃO DAS SUBCHAVES
INFO - Chave principal: 0x7365637265746b65
[PASSO] RODADA 1
INFO - L inicial: 32 bits
INFO - R inicial: 32 bits
[PASSO] Iniciando função F
...
```

## Funcionalidades do Logging

- **Geração de subchaves**: PC-1, shifts circulares, PC-2
- **16 rodadas Feistel**: Estado L/R, função F, XORs
- **S-boxes**: Entrada/saída de cada uma das 8 S-boxes
- **Permutações**: IP, E, P, FP
- **Conversões**: Bits ↔ inteiros, padding

## Aviso Importante

Esta implementação é para **fins educacionais apenas**. O DES é considerado criptograficamente inseguro pelos padrões atuais devido ao tamanho pequeno da chave (56 bits efetivos). Para aplicações reais, use algoritmos modernos como AES.

## Estrutura

```
des_implementation.py    # Implementação completa com logging
├── DESLogger           # Sistema de logging personalizado
├── Funções principais  # encrypt_message, decrypt_message
├── Algoritmo DES       # des_encrypt_block, des_decrypt_block
├── Função F            # Expansão, S-boxes, permutações
├── Geração de chaves   # des_key_schedule
└── Utilitários         # Conversões, padding
```

## Objetivos Educacionais

Este projeto ajuda a entender:
- Como funciona o algoritmo DES step-by-step
- Estrutura de redes Feistel
- Operações criptográficas básicas (XOR, permutações, substituições)
- Geração e uso de subchaves
- Padding e modos de operação

## Exemplo Completo

```python
# Configurar nível de detalhe
set_log_level(logging.INFO)

# Cifrar
message = "Texto secreto!"
key = "minhakey"
encrypted = encrypt_message(message, key)

# Decifrar
decrypted = decrypt_message(encrypted, key)

print(f"Original: {message}")
print(f"Cifrado:  {encrypted}")
print(f"Decifrado: {decrypted}")
```

## Recursos Educacionais

- Cada função tem documentação detalhada
- Logs mostram valores intermediários em hexadecimal e binário
- Implementação segue fielmente a especificação FIPS 46-3
- Código limpo e bem comentado para facilitar o estudo

---

**Nota**: Para uso em produção, utilize bibliotecas estabelecidas como `cryptography` ou `pycryptodome` com algoritmos modernos como AES-256.

**Referências:** https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
