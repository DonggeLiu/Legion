import pdb
import struct
import subprocess
import sys

import angr

INSTR_BINARY = sys.argv[1]
ORIGN_BINARY = sys.argv[2]
INPUT_STR = str.encode(''.join(sys.argv[3:]))


# TraceJump
def program(in_str):
    return tuple(traced_with_input(in_str))


def unpack(output):
    assert (len(output) % 8 == 0)

    addrs = []
    for i in range(int(len(output) / 8)):
        addr = struct.unpack_from('q', output, i * 8)  # returns a tuple
        addrs.append(addr[0])
    return addrs


def traced_with_input(in_str):
    p = subprocess.Popen(INSTR_BINARY, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if type(in_str) is not bytes:
        pdb.set_trace()
    (output, error) = p.communicate(in_str)
    addrs = unpack(error)

    return addrs


# Angr
def angr_addr(binary):
    proj = angr.Project(binary)
    entry = proj.factory.entry_state()
    entry.preconstrainer.preconstrain_file(INPUT_STR, entry.posix.stdin, True)
    simgr = proj.factory.simulation_manager(entry, save_unsat=True)
    addrs = []
    while simgr.active:
        addrs.append(simgr.active[0].addr)
        simgr.step()
    return addrs


def test_angr(binary, traces):
    proj = angr.Project(binary)
    entry = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(entry, save_unsat=True)
    addrs = [traces[0]]

    while simgr.active:
        keep = [state for state in simgr.active if state.addr in traces]
        keep.sort(key=lambda state: traces.index(state.addr))
        if keep:
            state = keep[0]
            pos = traces.index(state.addr)
            if len(simgr.active) > 1:
                addrs.append(state.addr)
                simgr.drop(lambda s: s != state)
            traces = traces[pos + 1:]

        assert len(simgr.active) == 1
        simgr.step()

    return addrs


if __name__ == '__main__':
    tj_addrs = program(INPUT_STR)
    print("TCJP", [hex(addr) for addr in tj_addrs])
    ar_addrs = angr_addr(INSTR_BINARY)
    print("Angr", [hex(addr) for addr in ar_addrs])
    assert (all([addr in ar_addrs for addr in tj_addrs]))
    # print("Angr", [hex(addr) for addr in angr_addr(ORIGN_BINARY)])
    print("Both", [hex(addr) for addr in test_angr(INSTR_BINARY, tj_addrs)])

# TCJP ['0x400889', '0x400557', '0x4005b3', '0x400608', '0x40062f', '0x400866', '0x400927']
# Angr ['0x400470', '0x1021ab0', '0x400980', '0x400428', '0x40043a', '0x4009b1', '0x4009b6', '0x400550', '0x4004e0', '0x400518', '0x4009cd', '0x4009d6', '0x4000040',
#       '0x400889', '0x40094a', '0x5000147', '0x400978', '0x40089c', '0x400460', '0x1110070', '0x4008de',
#       '0x400557', '0x40094a', '0x5000147', '0x400978', '0x40056a',
#       '0x4005b3', '0x40094a', '0x5000147', '0x400978', '0x4005c6',
#       '0x400608', '0x40094a', '0x5000147', '0x400978', '0x40061b',
#       '0x40062f', '0x40094a', '0x5000147', '0x400978', '0x400642',
#       '0x400866', '0x40094a', '0x5000147', '0x400978', '0x400879', '0x4008ec',
#       '0x400927', '0x40094a', '0x5000147', '0x400978', '0x40093a', '0x4000048', '0x4000048']
