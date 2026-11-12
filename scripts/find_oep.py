# Locate the ASPack 2.12 tail jump and print the OEP candidate.
# @category aspack-re
# @runtime Jython

# ASPack 2.12 wraps the real entry point in pushad ... popad ... jmp rel.
# The jmp hops into the last section, whose first byte is the original
# entry point. This script only reports; it does not patch the program.
#
# Run from the Script Manager against a loaded sample. Verify the candidate
# with verify/verify_oep.py before trusting it.

from ghidra.program.model.address import Address

MAX_SCAN = 0x2000
PUSHAD = 0x60
POPAD = 0x61
JMP_REL8 = 0xEB
JMP_REL32 = 0xE9

program = currentProgram
memory = program.getMemory()
listing = program.getListing()

def byte_at(addr):
    return program.getMemory().getByte(addr) & 0xff

def signed8(value):
    return value - 0x100 if value & 0x80 else value

def first_entry():
    it = program.getSymbolTable().getExternalEntryPointIterator()
    if it.hasNext():
        return it.next()
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(0)

def block_name(addr):
    block = memory.getBlock(addr)
    return block.getName() if block is not None else "?"

def executable(addr):
    block = memory.getBlock(addr)
    return block is not None and block.isExecute()

def looks_like_prologue(addr):
    prefix = []
    for delta in range(3):
        try:
            prefix.append(byte_at(addr.add(delta)))
        except Exception:
            break
    if prefix[:2] == [0x55, 0x8B] and prefix[2:3] == [0xEC]:
        return True
    if prefix[:2] == [0x55, 0x89] and prefix[2:3] == [0xE5]:
        return True
    return prefix[:2] == [0x55, 0x53]

entry = first_entry()
print("entry           0x%s (%s)" % (entry, block_name(entry)))

addr = entry
end = entry.add(MAX_SCAN)
saw_pushad = False
candidate = None

while addr.getOffset() < end.getOffset():
    try:
        value = byte_at(addr)
    except Exception:
        break

    if value == PUSHAD:
        saw_pushad = True
    elif value == POPAD:
        pass
    elif saw_pushad and value in (JMP_REL8, JMP_REL32):
        if value == JMP_REL8:
            target = addr.add(2).add(signed8(byte_at(addr.add(1))))
            width = 2
        else:
            rel = program.getMemory().getInt(addr.add(1))
            target = addr.add(5).add(rel)
            width = 5
        print("tail jump       0x%s  ->  0x%s" % (addr, target))
        print("jump bytes      %s" % " ".join("%02x" % byte_at(addr.add(i)) for i in range(width)))
        if executable(target) and memory.getBlock(target) != memory.getBlock(entry):
            candidate = target
        break

    addr = addr.add(1)

if candidate is None:
    print("no candidate: entry does not match the 2.12 pushad/popad/jmp shape")
else:
    print("OEP candidate   0x%s (%s)" % (candidate, block_name(candidate)))
    print("prologue match  %s" % looks_like_prologue(candidate))
    print("next: scripts/verify/verify_oep.py 0x%s" % candidate)
