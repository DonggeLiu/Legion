#!/usr/bin/env python3

# See AFL: afl-as.c
# http://lcamtuf.coredump.cx/afl/technical_details.txt

import sys

# import pdb


# registers used by __trace_jump
# rax, rdi, rsi, rdx

# registers used by write
# rcx, r11


NUM_SET = 0
NUM_TRACED = 0
JUMP_TARGETS = set()


def set_jump(output):
    global NUM_SET
    NUM_SET += 1

    output.append('\tsub $128,%rsp\n')
    output.append('\tpush %rax\n')
    output.append('\tcall\t__trace_jump_set\n')
    output.append('\tpop  %rax\n')
    output.append('\tadd $128,%rsp\n')


def trace_jump(output):
    global NUM_TRACED
    NUM_TRACED += 1

    output.append('\tsub $128,%rsp\n')
    output.append('\tpush %rax\n')
    output.append('\tpush %rdi\n')
    output.append('\tpush %rsi\n')
    output.append('\tpush %rdx\n')
    output.append('\tpush %rcx\n')
    output.append('\tpush %r11\n')
    output.append('\tcall\t__trace_jump\n')
    output.append('\tpop  %r11\n')
    output.append('\tpop  %rcx\n')
    output.append('\tpop  %rdx\n')
    output.append('\tpop  %rsi\n')
    output.append('\tpop  %rdi\n')
    output.append('\tpop  %rax\n')
    output.append('\tadd $128,%rsp\n')


def collect_jump_targets(asm_file):
    entry_label = False
    compare_set = False
    file = []

    lines = asm_file.readlines()

    for i in range(len(lines)):
        line = lines[i]
        instruction = line[:-1]
        if entry_label:
            # Case 0: TraceJump the beginning of Main()
            JUMP_TARGETS.add(instruction[:-1])
            entry_label = False

        # The Entry
        if instruction == "main:":
            # instrument the beginning of Main()
            entry_label = True

        # If the next instruction is a conditional jump
        # TraceJumpSet before the current one:
        if (i + 1) < len(lines):
            next_instruction = lines[i + 1]
            if next_instruction.startswith("\t"):
                if (next_instruction[1] == "j") and (
                        next_instruction[2] != "m"):
                    set_jump(file)
                    compare_set = True

        file.append(line)

        # Check each instructions:
        if instruction.startswith("\t"):

            if (instruction[1] == "j") and (instruction[2] != "m"):
                assert compare_set
                compare_set = False
                # Case 1: TraceJump after a label of conditional jump
                JUMP_TARGETS.add(instruction.split("\t")[2])
                # Case 2: TraceJump after conditional jump
                trace_jump(file)
    return file


def instrument_jump_targets(intermediate):
    file = []
    for line in intermediate:
        file.append(line)
        instruction = line[:-2]
        if instruction in JUMP_TARGETS:
            trace_jump(file)

    return file


def instrument():
    asm_file = open(asm, 'rt')
    ins_file = open(ins, 'wt')
    inter = collect_jump_targets(asm_file)
    final = instrument_jump_targets(intermediate=inter)
    ins_file.writelines(final)


if __name__ == "__main__" and len(sys.argv) > 2:
    asm = sys.argv[1]
    ins = sys.argv[2]
    instrument()
    print('SetJump   {} lines'.format(NUM_SET))
    print('TraceJump {} lines'.format(NUM_TRACED))
