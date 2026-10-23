# Ghidra script (Jython 2.7 compatible): analisar funcoes criticas de rede e chat
# Foco: buscar vulnerabilidades de RCE no chat multiplayer

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def get_function_at(addr_str):
    fm = currentProgram.getFunctionManager()
    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_str)
    return fm.getFunctionContaining(addr)

def decompile(addr_str):
    func = get_function_at(addr_str)
    if func is None:
        print("FUNCAO NAO ENCONTRADA para 0x" + addr_str)
        return None
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    result = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
    if result and result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None

print("=" * 70)
print("ANALISE DE SEGURANCA - SUB ROSA")
print("Foco: RCE no chat multiplayer")
print("=" * 70)

# 1. Funcao que processa /message (chat)
print("\n" + "=" * 70)
print("1. FUNCAO QUE PROCESSA /message (chat)")
print("=" * 70)
c = decompile("0x46856f")
if c:
    print(c)

# 2. Funcao de recepcao UDP (recvfrom)
print("\n" + "=" * 70)
print("2. FUNCAO DE RECEPCAO UDP (recvfrom)")
print("=" * 70)
c = decompile("0x4e071a")
if c:
    print(c)

# 3. Funcao de processamento de buffer UDP
print("\n" + "=" * 70)
print("3. FUNCAO DE PROCESSAMENTO DE BUFFER UDP")
print("=" * 70)
c = decompile("0x4e08d0")
if c:
    print(c)

# 4. Funcao de parsing de dados de jogador/rede (0x4c569a area)
print("\n" + "=" * 70)
print("4. FUNCAO DE PARSING DE DADOS DE JOGADOR (0x4c569a)")
print("=" * 70)
c = decompile("0x4c569a")
if c:
    print(c)

# 5. Funcao que processa config (0x4bc4e0)
print("\n" + "=" * 70)
print("5. FUNCAO DE PROCESSAMENTO DE CONFIG")
print("=" * 70)
c = decompile("0x4bc4e0")
if c:
    print(c)

# 6. Funcao de spawn de jogador (0x4bd740)
print("\n" + "=" * 70)
print("6. FUNCAO DE SPAWN DE JOGADOR")
print("=" * 70)
c = decompile("0x4bd740")
if c:
    print(c)
