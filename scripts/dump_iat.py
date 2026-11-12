# List import thunks that ASPack did not leave behind cleanly.
#
# ASPack 2.12 builds the import table at runtime, so Ghidra's import
# analysis often sees an empty IAT. After the program is unpacked, rebase
# and re-run analysis; unresolved call sites still show up as references
# into the EXTERNAL block, one per API. This script prints those call
# sites grouped by resolved name so each one can be fixed by hand.
#
# @category aspack-re
# @runtime Jython

from ghidra.program.model.symbol import SymbolType

program = currentProgram
refman = program.getReferenceManager()
symbols = program.getSymbolTable()
listing = program.getListing()

pending = {}

def note(name, from_addr, kind):
    pending.setdefault(name, []).append((str(from_addr), kind))

it = symbols.getSymbolIterator()
while it.hasNext():
    sym = it.next()
    if sym.getSymbolType() != SymbolType.FUNCTION:
        continue
    if not sym.isExternal():
        continue
    refs = refman.getReferencesTo(sym.getAddress())
    while refs.hasNext():
        ref = refs.next()
        start = ref.getFromAddress()
        instruction = listing.getInstructionAt(start)
        if instruction is None:
            continue
        note(sym.getName(), start, instruction.getMnemonicString())

if not pending:
    print("no external references: run analysis after dumping the IAT")
else:
    print("%d unresolved import name(s)" % len(pending))
    for name in sorted(pending):
        print("")
        print("%s" % name)
        for from_addr, kind in pending[name]:
            print("  0x%s  %s" % (from_addr, kind))

print("")
print("after patching, force re-analysis of the calling functions before trusting xrefs")
