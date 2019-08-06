import os
import sys


def instrument_c():
    if 'instrs' not in os.listdir('.'):
        os.mkdir('instrs')
    if 'inputs' not in os.listdir('.'):
        os.mkdir('inputs')
    assert C_FILE[-2:] == '.i'
    c_name = C_FILE.split("/")[-1]
    instr = C_FILE[:-2] + '.instr'
    os.system("cp {} ./".format(C_FILE))
    os.system("make {}".format(instr))
    os.system("rm ./{}".format(C_FILE.split("/")[-1]))
    return "./instrs/{}".format(c_name[:-2] + '.instr')


def run_legion():
    os.system("python3 ../Legion.py {} {} {}".format(
        sys.argv[1], sys.argv[2], BINARY))


if __name__ == '__main__':
    C_FILE = sys.argv[3]
    BINARY = instrument_c()
    run_legion()
