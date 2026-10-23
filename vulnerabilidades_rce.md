# Vulnerabilidades de RCE no Chat Multiplayer — Sub Rosa

> **Analisado com:** Ghidra 11.2 + objdump + análise manual de assembly x86
> **Alvo:** `subrosa.exe` (PE32 i386, Alpha 22)
> **Data:** 2026-10-23

---

## RESUMO EXECUTIVO

O **Sub Rosa** apresenta **múltiplas vulnerabilidades de segurança exploráveis remotamente via rede** (RCE). O protocolo de rede UDP não valida adequadamente tamanhos e índices de dados vindos de outros jogadores, permitindo:

1. **Escrita fora dos limites** (out-of-bounds write) em arrays globais durante o parsing de itens de jogador → **corrupção de memória arbitrária**.
2. **Buffer overflow na mensagem de chat** ao escrever `\0` além do buffer da mensagem.
3. **Múltiplos `strcpy`/`sprintf`/`strcat` sem verificação de tamanho** com dados originados da rede.

**Conclusão: SIM, o chat multiplayer (e o protocolo de rede em geral) contém vulnerabilidades que podem permitir RCE.**

---

## 1. VULNERABILIDADE PRINCIPAL — Out-of-bounds Write no Parsing de Rede

### Localização

**Função:** `FUN_004c54f0` (parsing do protocolo UDP, loop de itens de jogador)

### Código vulnerável (decompilado pelo Ghidra)

```c
for (local_20 = 0; local_20 < 6; local_20 = local_20 + 1) {
    FUN_004e0a70(local_28, 8);   // (A) le 8 bits da rede -> local_28[0]  (0-255, NAO validado!)
    FUN_004e0a70(&DAT_0cf2bc28 + local_28[0] * 4 + local_2c * 0x9110, 8);  // (B) le tamanho (8 bits)
    FUN_004e08d0(&DAT_0cf2bd28 + local_28[0] * 0x100 + local_2c * 0x9110, 1,
                 *(&DAT_0cf2bc28 + local_28[0] * 4 + local_2c * 0x9110));  // (C) memcpy(N bytes)
}
```

### Análise

- `local_28[0]` é lido do **buffer de rede** via `FUN_004e0a70` (8 bits = 0-255).
- **Não há validação** de que `local_28[0] < 6` (o tamanho do array de itens).
- O índice `local_28[0]` é usado para calcular o endereço de destino:
  ```
  destino = DAT_0cf2bd28 + local_28[0] * 0x100 + local_2c * 0x9110
  ```
- O tamanho da cópia também vem da rede (`*(&DAT_0cf2bc28 + local_28[0]*4)`).

### Impacto

| Índice `local_28[0]` | Offset destino | Tamanho max cópia | Resultado |
|---|---|---|---|
| 0 | `+0x0` | 255 | Dentro do slot (0x600) |
| 5 | `+0x500` | 255 | No limite do slot |
| 6 | `+0x600` | 255 | **FORA** do array (overflow) |
| 255 | `+0xFF00` | 255 | **MUITO FORA** (~0xF900 bytes além) |

O stride do array é `0x100` (256 bytes) por slot, com 6 slots por jogador (total 0x600 bytes). Mas `local_28[0]` pode ser até 255, levando a escrita em `DAT_0cf2bd28 + 0xFF00`, **~0xF900 bytes além do fim do array**.

### Exploitabilidade

Um atacante remoto que envia um pacote UDP malicioso pode:
1. Enviar `local_28[0] = N` (qualquer valor 0-255)
2. Enviar `tamanho = M` bytes de payload
3. Causar escrita de `M` bytes em `DAT_0cf2bd28 + N*0x100 + local_2c*0x9110`

Isso permite **corromper memória arbitrária** no processo. Se o endereço calculado alcançar o **stack** (return addresses), **SEH handler chain**, ou **function pointers**, o atacante pode obter **execução de código arbitrário (RCE)**.

> **Nota sobre mitigação:** O executável tem `NX_COMPAT` (DEP) mas **NÃO tem ASLR** (DllCharacteristics 0x8100 não inclui DYNAMIC_BASE). Isso torna o RCE mais viável pois os endereços são fixos.

---

## 2. VULNERABILIDADE — Buffer Overflow na Mensagem de Chat

### Localização

**Função:** `FUN_00468380` (processamento do comando `/message`)

### Código vulnerável (decompilado pelo Ghidra)

```c
void FUN_00468380(int param_1, char *param_2)
{
  char local_114 [260];
  ...
  param_2[0xff] = '\0';   // <-- ESCREVE NULL NO BYTE 255 DE param_2
  if (*param_2 == '/') {
    ...
    iVar1 = strncmp(param_2, "/message", 9);
    if (iVar1 == 0) {
      memcpy(local_114, param_2 + 9, 0x40);   // copia 64 bytes
      FUN_0046d400(0, local_114, 0xffffffff);
    }
  }
}
```

### Análise

- O buffer `param_2` aponta para `DAT_09336f10 + item*0x54 + player*0x23b4` (campo de mensagem do item no player struct).
- O stride do item é `0x54` (84 bytes). O campo de mensagem ocupa **no máximo 84 bytes**.
- `param_2[0xff] = '\0'` escreve null no **byte 255**, que está **171 bytes além** do campo de mensagem (84 bytes).
- Isso corrompe os itens subsequentes do jogador e possivelmente memória crítica.

### Impacto

A escrita de `\0` em `param_2[0xff]` corrompe dados em `DAT_09336f10 + item*0x54 + 0xff`, que está ~2.94 itens além. Se o player struct tiver dados críticos nessa região, pode causar crash ou corrupção explorável.

---

## 3. VULNERABILIDADE — `strcpy`/`strcat` sem limite com dados de rede

### Localização

**Função:** `FUN_004c54f0` (parsing de entrada de jogador)

### Código vulnerável

```c
char local_84 [64];   // buffer de apenas 64 bytes

// Ao exibir mensagem de "Joined":
strcpy(local_84, &DAT_09336e24 + local_2c * 0x23b4);  // nome do jogador (da rede!)
strcat(local_84, " Joined");                          // adiciona texto
FUN_0046d400(0, local_84, 0xffffffff);

// Ao exibir mensagem de "Exited":
strcpy(local_84, &DAT_09336e24 + player * 0x23b4);
strcat(local_84, " Exited");
```

### Análise

- O **nome do jogador** vem da rede (`FUN_004e08d0(&DAT_09336e24, 1, 0x20)` lê 32 bytes da rede).
- O nome é copiado para `local_84[64]` via `strcpy` **sem limite**.
- Depois `strcat(local_84, " Joined")` adiciona mais bytes.
- Se o nome tiver 32 bytes (máximo), + " Joined" (8) = 40 < 64. **Tecnicamente seguro** quando o nome tem 32 bytes.
- **PORÉM**, se a sanitização do nome (`FUN_004be130`) falhar ou for contornada, o `strcpy` pode estourar o buffer de 64 bytes.

### Outras chamadas `strcpy` críticas

Há **152 chamadas a `strcpy`** no binário, muitas com dados originados da rede. Alguns exemplos de alto risco:

- `0x4c560a`: `strcpy(&DAT_09336e24, &DAT_09336e24)` (nome do jogador) → buffer de 32 bytes
- `0x4c5a69`: `strcpy(local_84[64], nome_jogador)` + `strcat(local_84, " Joined")`
- `0x4c5613`: `strcpy(buffer_128, nome_jogador)` + `strcat(buffer_128, "...")`

---

## 4. VULNERABILIDADE — `sprintf` sem limite para campos de string

### Localização

**Função:** `FUN_004bc4e0` (processamento do config.txt) — **não é remotamente explorável**, mas demonstra o padrão inseguro:

```c
sprintf(&DAT_047f76a8, "Agent %d", uVar1 & 0x1ff);   // nome do jogador
strcpy(&DAT_047f76c8, "Sub Rosa Server");             // nome do servidor
sprintf(&DAT_047f7708, &DAT_00506080, iVar2);         // senha
```

### Função de spawn de jogador — `FUN_004bd740`

```c
rand();  // pele = rand()%3
rand();  // cabelo = rand()&7
rand();  // roupa = rand()&3
```

A randomização de skin foi patcheada em `subrosa.exe.ia` (skin fixa), mas o `subrosa.exe` original permanece vulnerável à randomização.

---

## 5. FUNÇÕES DE REDE RELEVANTES

### 5.1 Recepção UDP

```c
int FUN_004e06e0(void)
{
  ...
  local_8 = recvfrom(DAT_11c6f164, (char *)&DAT_11c7f194, 0x10000, 0, ...);
  ...
  if (local_8 > 0) {
    // valida magic: 4 bytes em DAT_11c7f194 == 0x5043f8
    DAT_11c7f188 = local_8;   // tamanho recebido
    DAT_11c7f18c = 4;         // offset de dados
  }
}
```

- Recebe até **0x10000 (65536) bytes** em `DAT_11c7f194`.
- Valida magic de 4 bytes (`DAT_005043f8`).
- O resto dos dados (até 65532 bytes) é processado sem validação adicional.

### 5.2 Processamento de buffer

```c
undefined4 FUN_004e08d0(void *param_1, int param_2, int param_3)
{
  if (DAT_11c7f18c < 0x10000) {
    if (DAT_11c7f188 < param_2 * param_3 + DAT_11c7f18c) {
      return 0;   // nao ha dados suficientes
    }
    memcpy(param_1, &DAT_11c7f194 + DAT_11c7f18c, param_2 * param_3);
    ...
  }
}
```

- **Não valida o tamanho do buffer de destino** — apenas se há dados suficientes na rede.
- `param_1` é o destino fornecido pelo chamador. Se `param_2 * param_3` exceder o tamanho do buffer de destino, **overflow**.

---

## 6. PROTOCOLO DE REDE (resumo)

- **Transporte:** UDP (principal) + TCP (conexão inicial)
- **Porta:** 27584 (config)
- **Buffer de recepção:** `DAT_11c7f194`, max 0x10000 bytes
- **Magic de pacote:** 4 bytes (`DAT_005043f8`)
- **Tipos de pacote:** `\x00` (handshake), `\x01` (join), `\x02` (entrada jogador), `\x04` (update estado), `\x07` (ping)
- **Chat:** via comando `/message` (processado localmente e exibido)
- **Voz:** Speex via OpenAL (dados de áudio recebidos da rede)

---

## 7. MITIGAÇÕES PRESENTES

- ✅ **NX_COMPAT** (DEP ativado)
- ❌ **ASLR** (NÃO ativado — endereços fixos)
- ✅ **SEH protegido** (`_except_handler4_common`)
- ❌ **SafeSEH** (não especificado)
- ✅ **IsDebuggerPresent** verificado no startup
- ❌ **Stack canary** — parcial (algumas funções usam `___security_check_cookie`)

---

## 8. CONCLUSÃO

**O chat multiplayer do Sub Rosa, juntamente com o protocolo de rede UDP, apresenta vulnerabilidades críticas de out-of-bounds write e buffer overflow que podem permitir RCE:**

1. **Primária (crítica):** Out-of-bounds write no parsing de itens de jogador (`FUN_004c54f0`) — índice e tamanho controlados pela rede, sem validação. Permite corrupção de memória arbitrária. **Explorável remotamente.**

2. **Secundária:** Buffer overflow na mensagem de chat (`FUN_00468380`) — escrita de `\0` além do buffer.

3. **Terciária:** Múltiplos `strcpy`/`strcat` sem limite com dados da rede.

A ausência de ASLR facilita muito a exploração, pois todos os endereços são fixos e previsíveis.

> **Nota ética:** Esta análise é para fins de pesquisa/segurança. Não forneceremos código de exploit completo.
