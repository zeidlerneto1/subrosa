from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def decompile_at(addr_str):
    fm = currentProgram.getFunctionManager()
    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_str)
    func = fm.getFunctionContaining(addr)
    if func is None:
        print("NAO ENCONTRADA: " + addr_str)
        return
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    result = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
    if result and result.decompileCompleted():
        print(result.getDecompiledFunction().getC())
    else:
        print("Falha em " + addr_str)

# Funcao que chama FUN_00468380 (processamento de chat)
# Precisamos encontrar quem chama 0x468380 e com que buffer
# Vamos procurar as referencias cruzadas usando Ghidra API

print("="*70)
print("REFERENCIAS A FUN_00468380 (chat)")
print("="*70)
fm = currentProgram.getFunctionManager()
addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("0x468380")
func = fm.getFunctionAt(addr)
if func:
    refs = currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())
    for ref in refs:
        print("  Chamada de: " + ref.getFromAddress().toString())
else:
    print("Funcao 0x468380 nao encontrada")
