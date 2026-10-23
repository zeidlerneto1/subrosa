# Relatório de Engenharia Reversa — Sub Rosa

> **Executável:** `subrosa.exe` (original, não patcheado)  
> **Data:** 2026-10-23  
> **Analista:** Kimi Code CLI  

---

## 1. INFORMAÇÕES BÁSICAS DO BINÁRIO

| Atributo | Valor |
|---|---|
| Formato | PE32 (Portable Executable 32-bit) |
| Arquitetura | i386 (x86, little-endian) |
| Tamanho | 1.671.680 bytes (~1.6 MB) |
| ImageBase | `0x00400000` |
| EntryPoint | `0x004ee212` |
| Subsystem | Windows GUI (2) |
| Linker | MSVC 10.0 (Visual Studio 2010) |
| Timestamp PE | `Thu Aug 14 19:04:26 2014` |
| Características | 0x0102 (EXECUTABLE, 32BIT_WORD) |
| DllCharacteristics | 0x8100 (NX_COMPAT, TERMINAL_SERVICE_AWARE) |
| OS Version alvo | Windows 5.1 (XP) |
| Stack Reserve | 1 MB |
| Heap Reserve | 1 MB |

---

## 2. SEÇÕES DO PE

| Seção | VMA | Tamanho | File Offset | Permissões | Conteúdo |
|---|---|---|---|---|---|
| `.text` | `0x00401000` | `0x0EDB9C` (950.9 KB) | `0x000400` | R-X | Código executável |
| `.rdata` | `0x004EF000` | `0x002516` (9.4 KB) | `0x0EE000` | R-- | Dados somente leitura, imports |
| `.data` | `0x004F2000` | `0x014A00` (82.5 KB) | `0x0F0600` | RW- | Dados globais, strings, vars |
| `.reloc` | `0x2009C000` | `0x092C58` (586.9 KB) | `0x105000` | R-- | Tabela de realocações |
| `.cave` | `0x2012F000` | `0x000400` (1 KB) | `0x197E00` | RWX | Espaço livre p/ código injetado |

> **Nota:** A seção `.cave` é executável E gravável — criada especificamente para permitir injeção de código.

---

## 3. DLLS IMPORTADAS E FUNÇÕES

### 3.1 SDL2.dll (33 funções)
Janelas, input, áudio, joystick, GL context:
`SDL_Init`, `SDL_CreateWindow`, `SDL_GL_CreateContext`, `SDL_GL_SetSwapInterval`,
`SDL_GL_SwapWindow`, `SDL_PollEvent`, `SDL_PumpEvents`, `SDL_Delay`, `SDL_GetTicks`,
`SDL_GetKeyboardState`, `SDL_GetMouseState`, `SDL_GetRelativeMouseState`,
`SDL_SetRelativeMouseMode`, `SDL_ShowCursor`, `SDL_SetWindowSize`, `SDL_SetWindowFullscreen`,
`SDL_GL_SetAttribute`, `SDL_GL_GetAttribute`, `SDL_JoystickUpdate`, `SDL_NumJoysticks`,
`SDL_JoystickOpen`, `SDL_JoystickGetAxis`, `SDL_JoystickGetButton`, `SDL_JoystickGetHat`,
`SDL_JoystickGetGUID`, `SDL_JoystickNameForIndex`, `SDL_JoystickNumAxes`, `SDL_JoystickNumButtons`,
`SDL_JoystickNumHats`, `SDL_HapticOpenFromJoystick`, `SDL_JoystickInstanceID`,
`SDL_JoystickEventState`, `SDL_RWFromFile`, `SDL_LoadWAV_RW`, `SDL_FreeWAV`,
`SDL_iconv_string`, `SDL_malloc`, `SDL_free`, `SDL_wcslen`, `SDL_isspace`,
`SDL_SetMainReady`, `SDL_GetDisplayMode`, `SDL_GetNumDisplayModes`

### 3.2 OPENGL32.dll (62 funções)
Renderização 3D completa com fixed-function pipeline:
`glBegin/End`, `glVertex2f/3f/2fv/3fv`, `glTexCoord2f/2fv`, `glColor3f/3fv/4f`,
`glNormal3fv`, `glEnable/Disable`, `glEnableClientState/DisableClientState`,
`glMatrixMode`, `glLoadIdentity`, `glMultMatrixf`, `glOrtho`, `glFrustum`, `glViewport`,
`glTranslatef`, `glScalef`, `glLightfv`, `glClear`, `glClearColor`, `glClearStencil`,
`glDepthFunc/Mask`, `glStencilFunc/Mask/Op`, `glColorMask`, `glBlendFunc`, `glLineWidth`,
`glPointSize`, `glPolygonMode`, `glFrontFace`, `glReadPixels`, `glReadBuffer`,
`glDrawArrays`, `glDrawElements`, `glVertexPointer`, `glColorPointer`, `glTexCoordPointer`,
`glNormalPointer`, `glGenTextures`, `glBindTexture`, `glTexImage2D`, `glTexParameteri/f`,
`glCopyTexSubImage2D`, `glFlush`, `glFinish`, `glGetString`, `glPushMatrix`, `glPopMatrix`,
`wglGetProcAddress`, `wglGetCurrentDC`

### 3.3 OpenAL32.dll (32 funções)
Áudio 3D posicional com captura de microfone:
`alGenSources`, `alGenBuffers`, `alSourcePlay/Stop/Pause`, `alSourcei/f/3f/fv`,
`alBufferData`, `alListenerf/fv`, `alGetError`, `alGetString`, `alSourceQueueBuffers`,
`alSourceUnqueueBuffers`, `alGetSourcei`, `alcOpenDevice`, `alcCloseDevice`,
`alcCreateContext`, `alcMakeContextCurrent`, `alcDestroyContext`, `alcGetCurrentContext`,
`alcGetContextsDevice`, `alcGetString`, `alcGetIntegerv`, `alcCaptureOpenDevice`,
`alcCaptureCloseDevice`, `alcCaptureStart`, `alcCaptureStop`, `alcCaptureSamples`

### 3.4 WSOCK32.dll (22 funções, por ordinal)
Rede Winsock 1.1 (sockets UDP/TCP):
`socket`, `bind`, `connect`, `closesocket`, `recv`, `recvfrom`, `send`, `sendto`,
`select`, `getsockopt`, `setsockopt`, `htonl`, `htons`, `ntohl`, `ntohs`,
`inet_ntoa`, `ioctlsocket`, `WSAAsyncGetHostByAddr`, `WSAAsyncGetServByName`,
`WSAAsyncGetProtoByName`, `WSAStartup`

### 3.5 libspeex.dll (13 funções)
Codec de voz:
`speex_encoder_init`, `speex_encoder_destroy`, `speex_encoder_ctl`, `speex_encode`,
`speex_bits_init`, `speex_bits_destroy`, `speex_bits_reset`, `speex_bits_write`,
`speex_bits_read_from`, `speex_decoder_init`, `speex_decoder_destroy`, `speex_decode`,
`speex_lib_get_mode`

### 3.6 MSVCR100.dll (funções C runtime)
`malloc`, `free`, `realloc`, `memcpy`, `memset`, `sprintf`, `sscanf`, `printf`,
`fprintf`, `fopen`, `fclose`, `fread`, `fwrite`, `fseek`, `ftell`, `feof`, `fgetc`,
`fputc`, `strlen`, `strcpy`, `strcat`, `strcmp`, `strncmp`, `strtol`, `rand`, `srand`,
`sqrt`, `pow`, `exp`, `sin`, `cos`, `tan`, `acos`, `atan2`, `floor`, `fabs`, `ldexp`,
`abs`, `qsort`, `toupper`, `_time64`, `_tzset`, `_sleep`, `_chdir`, `_findfirst64i32`,
`_findnext64i32`, `_findclose`, `_acmdln`, `_fmode`, `_commode`, `__set_app_type`,
`__getmainargs`, `_initterm`, `_initterm_e`, `_cexit`, `_exit`, `_XcptFilter`,
`_amsg_exit`, `_invoke_watson`, `_except_handler4_common`, `_lock`, `_unlock`,
`_onexit`, `__dllonexit`, `?terminate@@YAXXZ`, `_controlfp_s`, `_ismbblead`

### 3.7 SHELL32.dll (1 função)
`ShellExecuteA` — usado para abrir links (nvidia.com, amd.com, intel.com, twitter.com/crypticsea)

### 3.8 KERNEL32.dll (20 funções)
`GetCommandLineW`, `GetCurrentProcessId`, `GetCurrentThreadId`, `GetTickCount`,
`QueryPerformanceCounter`, `DecodePointer`, `EncodePointer`, `IsDebuggerPresent`,
`SetUnhandledExceptionFilter`, `UnhandledExceptionFilter`, `TerminateProcess`,
`IsProcessorFeaturePresent`, `GetStartupInfoW`, `HeapSetInformation`,
`InterlockedCompareExchange`, `InterlockedExchange`, `Sleep`, `GetCurrentProcess`,
`GetProcessAffinityMask`, `SetProcessAffinityMask`, `GetSystemTimeAsFileTime`

---

## 4. ARQUIVOS DE DADOS REFERENCIADOS

### 4.1 Shaders (GLSL 1.10, 9 pares vertex/fragment)
| Shader | Função |
|---|---|
| `shader/sector.glvs/glfs` | Renderização de setores/cidade — **scattering atmosférico** (8 amostras raio-traçado), shadow map, occlusion, reflexões |
| `shader/model.glvs/glfs` | Modelos 3D (personagens, veículos) — iluminação difusa/ambiental + specular + shadow + occlusion |
| `shader/atmosphere.glvs/glfs` | Skybox/atmosfera — scattering atmosférico full com fase Mie + Rayleigh |
| `shader/depth.glvs/glfs` | Pass de profundidade (depth map para shadow/occlusion) |
| `shader/occlusion.glvs/glfs` | SSAO (Screen-Space Ambient Occlusion), 8 amostras |
| `shader/shadow.glvs/glfs` | Pass de sombras (simples: `gl_FragColor=gl_Color`) |
| `shader/reflect.glvs/glfs` | Reflexões por raio-traçado com scattering |
| `shader/blur.glvs/glfs` | Blur gaussiano (8 taps) para suavizar shadow/occlusion |
| — | — |

### 4.2 Texturas (PNG)
`texture/font01.png`, `texture/font02.png`, `texture/dotmatrixfont.png`,
`texture/mouse01.png`, `texture/times.png`, `texture/twitter01.png`,
`texture/cash_dollar.png`, `texture/cash_five.png`, `texture/cash_ten.png`,
`texture/cash_twenty.png`, `texture/cash_fifty.png`, `texture/cash_hundred.png`,
`test/m16.png`

### 4.3 Sons (WAV)
`44magnum.wav`, `4cylinder.wav`, `bullethitbody01.wav`, `bullethitbody02.wav`,
`bullethitmetal01.wav`, `bullethitmetal02.wav`, `carcrash01.wav`, `carcrash02.wav`,
`gearshift01.wav`, `glassbreak01.wav`, `helicopter02.wav`, `phonering01.wav`,
`reload01.wav`, `ricochet%02d.wav` (01-07), `shell_hit_cement.wav`,
`submachinegun01.wav`, `tiresqueal.wav`

### 4.4 Dados do jogo
| Arquivo | Formato | Conteúdo |
|---|---|---|
| `data/city.sbc` | Binário | Cidade: header com magic `0x05`, contagem de edifícios, coordenadas/rotação |
| `data/building%03d.sbb` | Binário | Edifícios: magic `0x05`, nome string, grade de sectores com propriedades |
| `user/client.srk` | Binário | Dados de skin do jogador (pele, cabelo, roupa + hash) |
| `user/server.srk` | Binário | Dados do servidor (credenciais) |
| `config.txt` | Texto | Opções do jogo |
| `shaderoutput.txt` | Texto | Log de shaders |

---

## 5. JOGABILIDADE (MECÂNICAS)

### 5.1 Objetivo do jogo
Sub Rosa é um **jogo multiplayer de crime corporativo** onde as empresas competem:

- **Corporações**: Goldmen Inc, Monsota, Nexaco, Megacorp
- **Objetivo**: Comprar/vender **discos** (Black, Blue, Green, Gold, Red, White)
  contendo informações valiosas que podem ser negociadas entre corporações
- **Mecânicas de missão**: receber relatórios de localização de discos
  (`"We have received reports that /s has acquired a disk..."`), entregá-los
  para obter dinheiro
- **Briefcase**: maleta para transportar discos e dinheiro
- **Banking**: depositar/retirar dinheiro, comprar/vender ações
- **Dinheiro**: notas de $1, $5, $10, $20, $50, $100

### 5.2 Armas e equipamento
| Arma | Magazine |
|---|---|
| 9mm | 9mm Magazine |
| MP5 | MP5 Magazine |
| AK-47 | AK-47 Magazine |
| M-16 | M-16 Magazine |
| Magnum | (revólver) |

Sistema de **magazines duplas** (Shift+2-5 para equipar, Shift+R para carregar,
Shift+Tilde para descartar), **Bandage** (curativo), **Fancy Suit**, **Cell Phone**.

### 5.3 Veículos
`Town Car`, `Town Car 2`, `Beamer`, `Minivan`, `Goldmen`, `Monsota`, `Nexaco`

### 5.4 Controles
- **Tab**: Menu
- **1**: Freecam
- **C**: Toggle info
- **E**: Exit
- **F**: Trocar arma de mão
- **F1**: Toggle help
- **Space**: Trocar jogador
- **Shift+2-5**: Equipar magazine
- **Shift+R**: Carregar magazine/objeto na maleta
- **Shift+Tilde**: Descartar magazine
- **Numpad/números**: Seleção

### 5.5 Modos de jogo
- **Join** (multiplayer online via serverinfo.php)
- **Start** (hostear servidor local)
- **Demo** / **Demo 2** (bots locais)
- **Direct IP** (conexão por IP)
- **Broadcast** (LAN)

### 5.6 Times
`Team 1+2`, `Team 1+3`, `Team 2+3`, `All Teams`, `team 5`, `team 6`, `team 7`

---

## 6. PROTOCOLO DE REDE

### 6.1 Servidor de listagem
```
GET /anewzero/serverinfo.php HTTP/1.1
Host:www.crypticsea.com
```
O cliente consulta `www.crypticsea.com` para obter a lista de servidores.

### 6.2 Rede
- **Porta padrão**: `27584` (config.txt)
- **Protocolo**: UDP (Winsock, com `sendto`/`recvfrom`) + TCP para alguns casos
- **Voz**: codec Speex, captura via OpenAL (`alcCapture*`), push-to-talk
- **Rate limit**: `servermaxbytespersecond=100000`
- **Comandos**: `/admin`, `/kick`, `/message`, `/resetgame`

### 6.3 Formato de mensagens
- `objpacketsize:/i`, `Packetsize:/i`, `users=%d`, `Clients:/i`, `ClientRound:/i`

---

## 7. PIPELINE GRÁFICO

O renderer usa um **pipeline de renderização multi-pass** com OpenGL 2.0:

1. **Pass de profundidade** (`depth.glfs`) — gera depth map
2. **Pass de sombras** (`shadow.glfs`) — renderiza sombras
3. **SSAO** (`occlusion.glfs`) — oclusão ambiente em espaço de tela (8 amostras)
4. **Blur** (`blur.glfs`) — suaviza sombras/occlusion (gaussiano 8 taps)
5. **Renderização principal** (`sector.glfs`/`model.glfs`) — com scattering atmosférico
6. **Atmosfera/sky** (`atmosphere.glfs`) — raio-traçado com fase Mie/Rayleigh
7. **Reflexões** (`reflect.glfs`) — reflexos por raio-traçado

Características notáveis:
- **Scattering atmosférico** com 8 amostras de raio-traçado
- **Shadow mapping** com blur
- **SSAO** (screen-space ambient occlusion)
- **Reflexões por raio-traçado**
- **Iluminação difusa/ambiente/specular**
- **Texturas com canal alpha** para brilho/reflexo

---

## 8. ESTRUTURA DE DADOS (ENGENHARIA REVERSA DE CÓDIGO)

### 8.1 Função de spawn de jogador (`0x4BD740`)

```
0x4bd740: push ebp; mov ebp,esp; sub esp,0x10
0x4bd746: call 0x4bd9c0          ; obter slot livre (retorna -1 se cheio)
0x4bd74b: mov [ebp-0xc], eax     ; salvar índice do jogador
0x4bd75e: ...                    ; memset do player struct (0x23b4 = 9108 bytes)
0x4bd7cf: mov [player+0x5c], 0x1388  ; health = 5000
0x4bd7d9: ...                    ; loop zera inventário (8 slots de 0x64)
0x4bd83a: call rand              ; rand() & 0xf → posição aleatória
0x4bd863: ...                    ; inicializa posição, rotação, escala
0x4bd94b: call rand  → pele   = rand() % 3      → [player+0x93391c0]
0x4bd968: call rand  → cabelo = rand() & 7      → [player+0x93391c4]
0x4bd980: call rand  → roupa  = rand() & 3      → [player+0x93391c8]
0x4bd998: mov [player+0x9338f64], -1
0x4bd9ab: mov eax, [ebp-0xc]     ; retorna índice do jogador
```

### 8.2 Processamento do config.txt (`0x4BC4E0`)

```
0x4bc4e0: push ebp; mov ebp,esp; sub esp,0x50
0x4bc4e6: cmp [ebp+8],0          ; arg==0 → leitura, arg!=0 → escrita
0x4bc4f0: ...                    ; seta defaults (screenwidth=1024, screenheight=640, etc.)
0x4bc676: push 0x506090, 0x506094
0x4bc680: call fopen             ; abre config.txt
0x4bc689: mov [0xdea7da8], eax   ; FILE* global do config
0x4bc69c: ...                    ; para cada chave: call 0x4bc8d0(dest, chave, [ebp+8])
0x4bc6a0: "screenwidth="  → [0xfaf0860]
0x4bc6b2: "screenheight=" → [0xfaf0864]
0x4bc6c2: "colordepth="   → [0xfaf0868]
0x4bc6d8: "depthbits="    → [0xfaf086c]
0x4bc6f4: "stencilbits="  → [0xfaf0870]
0x4bc70a: "fullscreen="   → [0xfaf0874]
0x4bc720: "joystick="     → [0xfaf0878]
0x4bc736: "sound="        → [0xfaf0880]
... (continua para todas as chaves)
```

### 8.3 Variáveis globais importantes (`.data`)

| Endereço | Descrição |
|---|---|
| `0x506090` | `"screenwidth="` |
| `0x5060a0` | `"screenheight="` |
| `0x5060b0` | `"colordepth="` |
| `0x5060c0` | `"depthbits="` |
| `0x5060cc` | `"stencilbits="` |
| `0x5060d8` | `"fullscreen="` |
| `0x5060e8` | `"joystick="` |
| `0x5060f4` | `"sound="` |
| `0x506100` | `"soundvolume="` |
| `0x506108` | `"musicvolume="` |
| `0x506118` | `"port=%d"` |
| `0x47f7758` | `"servermaxbytespersecond="` |
| `0x47f775c` | `"name="` |
| `0xfaf0860` | screenwidth |
| `0xfaf0864` | screenheight |
| `0xfaf0868` | colordepth |
| `0xfaf086c` | depthbits |
| `0xfaf0870` | stencilbits |
| `0xfaf0874` | fullscreen |
| `0xfaf0878` | joystick |
| `0xfaf0880` | sound |
| `0xdea7da8` | FILE* do config.txt |
| `0x9336e20` | array de jogadores (struct 0x23b4 bytes cada) |

### 8.4 Struct do jogador (0x23B4 = 9108 bytes)

| Offset | Campo |
|---|---|
| `+0x00` | ativo (bool) |
| `+0x34` | id do jogador |
| `+0x3C` | health (0x1388 = 5000) |
| `+0x5C` | arma? |
| `+0x8C` | — |
| `+0xCC` | — |
| `+0x2100` | posição (vec3) |
| `+0x2104` | posição y |
| `+0x2108` | posição z |
| `+0x2110` | escala |
| `+0x2118` | — |
| `+0x211C` | — |
| `+0x2120` | — |
| `+0x2124` | — |
| `+0x2128` | — |
| `+0x212C` | — |
| `+0x2190` | — |
| `+0x21C0` | pele (0-2) |
| `+0x21C4` | cabelo (0-7) |
| `+0x21C8` | roupa (0-3) |
| `+0x19A4` | — |

---

## 9. STRINGS DE MENU (localização em memória)

### 9.1 Menu principal (~VA `0x5042F0`)
```
Exit, Options, Voice Options, Join, Start, Demo, Demo 2,
Twitter, CrypticSea, Name, Sub Rosa, ALPHA 22, DEBUG,
www.twitter.com/crypticsea, www.crypticsea.com,
NVidia webpage, ATI/AMD webpage, Intel webpage,
OpenGL 2.0 required, Make sure you have the latest drivers for your video card,
GL_VERSION: /s, GL_VENDOR: /s, GL_RENDERER: /s,
www.nvidia.com, www.amd.com, www.intel.com
```

### 9.2 Menu de opções (~VA `0x5037C0`+)
```
Server Name, Max Players, Round Length, Players,
Broadcast, Direct IP, Cancel,
Voice Chat, Voice Options, Voice Minimum, Use push to talk,
Press key for voice push to talk,
Resolution, Fullscreen, Sound Volume, Music Volume, Invert Mouse
```

### 9.3 Strings de gameplay (~VA `0x503800`+)
```
Observer, Spectating, Weapons, Equipment, Banking, Buy Share, Sell Share,
Buy 10 Shares, Buy 100 Shares, Sell 10 Shares, Sell 100 Shares,
Bandage, Fancy Suit, Cash, Briefcase, Open Briefcase, Cell Phone,
Black Disk, Blue Disk, Green Disk, Gold Disk, Red Disk, White Disk,
9mm, MP5, AK-47, M-16, Magnum,
9mm Magazine, MP5 Magazine, AK-47 Magazine, M-16 Magazine,
Deposit, Withdrawl $1/5/10/20/50/100,
Kick Player, Team: , Team 1+2:, Team 1+3:, Team 2+3:, All Teams:
```

### 9.4 Strings de missões (~VA `0x503210`)
```
Missions:,
We have received reports that Megacorp has disks containing
information that will be beneficial to one of our subsidiaries.,
We do not know where the disk is located.,
The /s is in a building near the
The /s is in a limo driving around randomly.
/s and /s intersection
Value:               $/i Bonus
We have received reports that /s has acquired a disk
We have acquired a disk that has information that can be
containing information that will be beneficial to one of our
subsidiaries.  Negotiate the best terms and execute the deal.
subsidiaries.  Acquire the disk by any means neccessary.
This mission expires at /i:/i/i
No current missions
You have been provided with $/i.
```

---

## 10. PATCHES ANTERIORES (SKIN FIXA)

O arquivo `subrosa.md` documenta modificações prévias para skin fixa:

| Endereço VA | File Offset | Patch |
|---|---|---|
| `0x4BD94B` | `0xBCD4B` | `call rand` → `mov eax,[0x506968]` (pele) |
| `0x4BD968` | `0xBCD68` | `call rand` → `mov eax,[0x50696C]` (cabelo) |
| `0x4BD980` | `0xBCD80` | `call rand` → `mov eax,[0x506970]` (roupa) |
| `0x4BC8AF` | `0xBBCAF` | `jmp 0x2012F20A` (código no .cave) |

> **Nota:** O `subrosa.exe` atual é o ORIGINAL (não patcheado).
> O `subrosa.exe.ia` é a versão PATCHADA com skin fixa.

---

## 11. COMPILAÇÃO E FERRAMENTAS

- **Compilador**: MSVC 10.0 (Visual Studio 2010), C++
- **C Runtime**: MSVCR100.dll
- **Bibliotecas**: SDL2, OpenGL, OpenAL, libspeex, Winsock
- **Versão**: Alpha 22
- **Distribuidor**: CrypticSea (www.crypticsea.com)
- **Formato de debug**: sem símbolos de debug (stripped), mas com `.idb` (IDA Pro database) disponível

---

## 12. ANÁLISE DE SEGURANÇA

- **NX_COMPAT**: ativado (DEP)
- **ASLR**: não ativado (DllCharacteristics 0x8100 não inclui DYNAMIC_BASE 0x40)
- **SEH**: usa `_except_handler4_common` (proteção contra SEH overwrite)
- **SafeSEH**: não especificado (não há SEH table)
- **IsDebuggerPresent**: verificado no startup
- **Buffer overflows**: strings com `sprintf` sem limite (potencialmente vulnerável)
- **Config**: arquivo texto sem criptografia
- **Rede**: protocolo não criptografado (voz via Speex sem criptografia)

---

## 13. RESUMO EXECUTIVO

**Sub Rosa** é um jogo multiplayer de crime corporativo em 3D (estilo GTA),
desenvolvido pela CrypticSea (lançado como Alpha 22 em 2014). Utiliza:

- **SDL2** para janelas/input/áudio
- **OpenGL 2.0** com pipeline multi-pass customizado (shadow mapping, SSAO,
  scattering atmosférico, reflexões raio-traçadas)
- **OpenAL + Speex** para chat de voz
- **Winsock** para networking UDP/TCP
- **Sistema de sectores** para o mundo (cidade + edifícios)
- **Sistema de missões** baseado em discos corporativos com valor monetário
- **Economia** com depósitos bancários, ações e dinheiro físico
