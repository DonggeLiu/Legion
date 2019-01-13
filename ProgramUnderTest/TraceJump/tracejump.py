#!/usr/bin/env python

# See AFL: afl-as.c
# http://lcamtuf.coredump.cx/afl/technical_details.txt

import sys

code_sections = [
    '\t.text\n',
    '\t.section\t.text',
    '\t.section\t__TEXT,__text',
    '\t.section __TEXT,__text'
    ]

data_sections = [
    '\t.section',
    '\t.',
    '\t.',
    '\t.'
    ]

is64 = True

# registers used by __trace_jump
# rax, rdi, rsi, rdx

# registers used by write
# rcx, r11


def trace_jump(output):
    assert is64

    # output.write('.align 4\n')
    output.write('\tsub $128,%rsp\n')
    output.write('\tpush %rax\n')
    output.write('\tpush %rdi\n')
    output.write('\tpush %rsi\n')
    output.write('\tpush %rdx\n')
    output.write('\tpush %rcx\n')
    output.write('\tpush %r11\n')
    output.write('\tcall\t__trace_jump\n')
    output.write('\tpop  %r11\n')
    output.write('\tpop  %rcx\n')
    output.write('\tpop  %rdx\n')
    output.write('\tpop  %rsi\n')
    output.write('\tpop  %rdi\n')
    output.write('\tpop  %rax\n')
    output.write('\tadd $128,%rsp\n')


# see afl-as.c add_instrumentation
def instrument():
    global data_sections, is64
    
    ins_lines = 0
    instr_ok = False
    skip_csect = False
    skip_next_label = False
    skip_intel = False
    skip_app = False
    instrument_next = False

    for line in asm_file:
        if not skip_intel and not skip_app and not skip_csect and instr_ok and instrument_next and line[0] == '\t' and str.isalpha(line[1]):
            trace_jump(ins_file)
            ins_lines += 1
            instrument_next = False

        ins_file.write(line)

        if line[0] == '\t' and line[1] == '.':
            if line == '\t.text\n' or line.startswith('\t.section\t.text') or line.startswith('\t.section\t__TEXT,__text') or line.startswith('\t.section __TEXT,__text'):
                instr_ok = True
                continue
            
            if line == '\t.bss\n' or line == '\t.data\n' or line.startswith('\t.section\t') or line.startswith('\t.section '):
                instr_ok = False
                continue
            
            if '.code' in line:
                if '.code32' in line:
                    is64 = False
                if '.code64' in line:
                    is64 = True
                    
            if '.intel_syntax' in line:
                skip_intel = True
            if '.att_syntax' in line:
                skip_intel = False
                
        if line.startswith('##'):
            if '#APP' in line:
                skip_app = True
            if '#NO_APP' in line:
                skip_app = False
                
        if skip_intel or skip_app or skip_csect or not instr_ok or line[0] == '#' or line[0] == ' ':
            continue
        
        if line[0] == '\t':
            if line[1] == 'j' and line[2] != 'm':
                trace_jump(ins_file)
                ins_lines += 1
            continue
        
        if line[0] == '.' and ':' in line:
            if str.isdigit(line[2]):
                if not skip_next_label:
                    instrument_next = True
                else:
                    skip_next_label = False
            else:
                instrument_next = True
                    
    return ins_lines


if __name__ == "__main__" and len(sys.argv) > 2:
    asm_file = open(sys.argv[1], 'r')
    ins_file = open(sys.argv[2], 'w')
    print('instrumented {} lines'.format(instrument()))
