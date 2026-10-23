from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def get_function_at(addr_str):
    fm = currentProgram.getFunctionManager()
    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_str)
    return fm.getFunctionContaining(addr)

def decompile(addr_str):
    func = get_function_at(addr_str)
    if func is None:
        print("NAO ENCONTRADA: " + addr_str)
        return
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    result = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
    if result and result.decompileCompleted():
        print(result.getDecompiledFunction().getC())
    else:
        print("Falha ao decompilar " + addr_str)

print("="*70)
print("FUNCAO 0x4e0a70 (le N bytes do buffer de rede)")
print("="*70)
decompile("0x4e0a70")

print("="*70)
print("FUNCAO 0x4e0960 (adiciona bits ao buffer)")
print("="*70)
decompile("0x4e0960")

print("="*70)
print("FUNCAO 0x4be130 (sanitiza nome do jogador)")
print("="*70)
decompile("0x4be130")

print("="*70)
print("FUNCAO 0x46d400 (chat/msg display)")
print("="*70)
decompile("0x46d400")

print("="*70)
print("FUNCAO 0x4e07d0 (envia dados UDP)")
print("="*70)
decompile("0x4e07d0")
