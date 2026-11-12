# Score OEP candidates produced by scripts/find_oep.py.
#
# A candidate is only worth dumping if it sits in an executable section,
# is not the packer's own stub, and decodes to a plausible function
# prologue. The script prints one line per candidate and a 0-3 score:
#   1 = executable, non-stub section
#   2 = + first bytes look like a prologue
#   3 = + prologue is followed by a real stack frame setup
#
# Run with: verify/verify_oep.py 0x00401234 [0x0040a000 ...]
#
# @category aspack-re
# @runtime Jython

program = currentProgram
memory = program.getMemory()
stub_block = memory.getBlock(program.getSymbolTable().getExternalEntryPointIterator().next())

def byte_at(addr):
    try:
        return memory.getByte(addr) & 0xff
    except Exception:
        return None

def prologue(addr):
    got = [byte_at(addr.add(i)) for i in range(6)]
    if None in got:
        return 0
    if got[0] == 0x55 and got[1] == 0x8B and got[2] == 0xEC:
        return 1
    if got[0] == 0x55 and got[1] == 0x89 and got[2] == 0xE5:
        return 1
    if got[0] == 0x55 and got[1] in (0x53, 0x56, 0x57):
        return 1
    if got[0] in (0x68, 0x6A, 0x8B, 0xE8):
        return 1
    return 0

def stack_frame(addr):
    # sub esp, imm after the frame pointer set-up
    if byte_at(addr.add(3)) in (0x81, 0x83):
        return 1
    if byte_at(addr.add(3)) == 0xE8:
        return 1
    return 0

args = getScriptArgs()
if not args:
    print("usage: verify_oep.py <hex offset> [...]")
else:
    for raw in args:
        try:
            addr = toAddr(raw)
        except Exception:
            print("%s  unparsable" % raw)
            continue
        block = memory.getBlock(addr)
        if block is None or not block.isExecute():
            print("0x%s  score 0  not executable (%s)"
                  % (addr, block.getName() if block else "unmapped"))
            continue
        score = 1
        if block == stub_block:
            print("0x%s  score 1  inside the stub itself (%s), wrong candidate"
                  % (addr, block.getName()))
            continue
        if prologue(addr):
            score += 1
        if score == 2 and stack_frame(addr):
            score += 1
        verdict = {2: "weak: prologue only", 3: "plausible OEP"}.get(score, "check by hand")
        print("0x%s  score %d  %s  section=%s"
              % (addr, score, verdict, block.getName()))

print("")
print("score 3 alone is not proof; disassemble the first basic block before dumping")
