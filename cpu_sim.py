#!/usr/bin/env python3
import sys
import argparse   # ← new

DEBUG_MODE = 0

def dump_memory():
    """Print only registers, kernel area (0–20), and thread table to stderr."""
    # 1) Special registers
    regs = ["PC", "SP", "SYSCALL_RES", "INSTR_COUNT"]
    for i, name in enumerate(regs):
        print(f"{name:12s} [{i:3d}] = {memory[i]}", file=sys.stderr)

    # 2) Kernel area (0–20)
    print("\n-- Kernel mem[0–20] --", file=sys.stderr)
    for addr in range(0, 21):
        print(f"  {addr:4d} = {memory[addr]}", file=sys.stderr)

    # 3) Thread table
    start = THREAD_TABLE_START
    end   = THREAD_TABLE_START + NUM_THREADS*THREAD_ENTRY_SIZE
    print(f"\n-- Thread table [{start}–{end-1}] --", file=sys.stderr)
    for tid in range(NUM_THREADS):
        base = start + tid*THREAD_ENTRY_SIZE
        entry = memory[base:base+THREAD_ENTRY_SIZE]
        print(f" TID {tid:2d}: {entry}", file=sys.stderr)

def dump_thread_table():
    """Print tid | state | pc | sp for each thread to stderr."""
    print("\n-- THREAD TABLE DUMP --", file=sys.stderr)
    for tid in range(NUM_THREADS):
        base = THREAD_TABLE_START + tid*THREAD_ENTRY_SIZE
        state, pc, sp = memory[base+3], memory[base+4], memory[base+5]
        print(f"T{tid:2d} | st={state} | pc={pc:5d} | sp={sp:5d}", file=sys.stderr)
    print("-- end dump --\n", file=sys.stderr)
# ——————————————————————————————————————————————————————————————————————————
# CPU simulator with cooperative round-robin threading in Python
# ——————————————————————————————————————————————————————————————————————————

# 1) Define the total memory size
MEMORY_SIZE = 11000
memory = [0] * MEMORY_SIZE

# 2) “Special” registers
REG_PC          = 0    # program counter
REG_SP          = 1    # stack pointer
REG_SYSCALL_RES = 2    # (unused here)
REG_INSTR_COUNT = 3    # total instructions executed

STATE_READY      = 0  
STATE_RUNNING    = 1  
STATE_TERMINATED = 2  
STATE_BLOCKED    = 3  

# 3) Thread table layout: 6 words per thread
THREAD_TABLE_START = 21   # base address of thread-table
THREAD_ENTRY_SIZE  = 6    # [ tid | start_time | used_instrs | state | pc | sp ]
NUM_THREADS        = 11  # → now covers slots 0 through 9

# runtime state
current_thread   = None   # None or 0..NUM_THREADS-1
in_kernel        = True
halted           = False
saved_kernel_pc  = 0      # where to resume kernel after a USER

instruction_list = []


def incr_instr_count(amount=1):
    """Bump both the global __INSTR_COUNT__ and the per-thread count."""
    global in_kernel, current_thread
    memory[REG_INSTR_COUNT] += amount

    # OS (tid=0) if we're in kernel, else current_thread
    tid = 0 if in_kernel or current_thread is None else current_thread
    base = THREAD_TABLE_START + tid * THREAD_ENTRY_SIZE
    memory[base + 2] += amount


def check_user_access(addr):
    """Prevent a user thread from touching kernel addresses (<1000)."""
    global halted
    if not in_kernel and addr < 1000:
        # illegal access → block this thread
            base = THREAD_TABLE_START + current_thread*THREAD_ENTRY_SIZE
            memory[base + 3] = STATE_BLOCKED
            memory[87 + current_thread] += 1   # increment its block counter
            print(f"THREAD {current_thread} ILLEGAL ACCESS → BLOCKED")
            return False
    return True


def pick_next_thread(old_tid):
    """Round-robin: find the next slot whose 'state' == 0 (READY)."""
    start = -1 if old_tid is None else old_tid
    for i in range(1, NUM_THREADS + 1):
        tid = (start + i) % NUM_THREADS
        state = memory[THREAD_TABLE_START + tid * THREAD_ENTRY_SIZE + 3]
        if state == 0:
            return tid
    return None


def execute_one_instruction():
    global halted, in_kernel, saved_kernel_pc, current_thread

    pc = memory[REG_PC]
    if pc < 0 or pc >= len(instruction_list):
        incr_instr_count()
        halted = True
        return

    op, *args = instruction_list[pc]
    #mode = "KERNEL" if in_kernel else " USER "
    #print(f"[DEBUG] PC={pc:>4} MODE={mode} INSTR={(op,)+tuple(args)}")

    # — HLT
    if op == "HLT":
        incr_instr_count()
        halted = True
        return

    # — SET A→mem[B]
    if op == "SET":
        B, A = args
        if not check_user_access(A): return
        memory[A] = B
        incr_instr_count()
        if A == REG_PC: return

    # — CPY mem[A1]→mem[A2]
    elif op == "CPY":
        A1, A2 = args
        if not check_user_access(A2): return
        memory[A2] = memory[A1]
        incr_instr_count()
        if A2 == REG_PC: return

    # — ADD immediate B to mem[A]
    elif op == "ADD":
        A, B = args
        if not check_user_access(A): return
        memory[A] += B
        incr_instr_count()
        if A == REG_PC: return

    # — ADDI mem[A1]→mem[A2]
    elif op == "ADDI":
        A1, A2 = args
        if not check_user_access(A2): return
        memory[A2] += memory[A1]
        incr_instr_count()
        if A2 == REG_PC: return

    # — SUBI mem[A1] -= mem[A2]
    elif op == "SUBI":
        A1, A2 = args
        if not check_user_access(A1): return
        memory[A1] -= memory[A2]
        incr_instr_count()
        if A1 == REG_PC: return

    # — CPYI indirection: mem[mem[A1]]→mem[A2]
    elif op == "CPYI":
        A1, A2 = args
        addr = memory[A1]
        if not check_user_access(A2): return
        memory[A2] = memory[addr]
        incr_instr_count()
        if A2 == REG_PC: return

    # — PUSH A onto stack
    elif op == "PUSH":
        (A,) = args
        memory[REG_SP] -= 1
        if not check_user_access(memory[REG_SP]): return
        memory[memory[REG_SP]] = memory[A]
        incr_instr_count()
        if memory[REG_SP] == REG_PC: return

    # — POP from stack into A
    elif op == "POP":
        (A,) = args
        if not check_user_access(A): return
        memory[A] = memory[memory[REG_SP]]
        memory[REG_SP] += 1
        incr_instr_count()
        if A == REG_PC: return

    # — CALL C: push ret, PC=C
    elif op == "CALL":
        (C,) = args
        ret = memory[REG_PC] + 1
        memory[REG_SP] -= 1
        if not check_user_access(memory[REG_SP]): return
        memory[memory[REG_SP]] = ret
        memory[REG_PC] = C
        incr_instr_count()
        return

    # — RET: pop into PC
    elif op == "RET":
        ret = memory[memory[REG_SP]]
        memory[REG_SP] += 1
        memory[REG_PC] = ret
        incr_instr_count()
        return

    # — USER A: thread entry at address A
    elif op == "USER":
        (A,) = args
        tid  = (A - 1000) // 1000
        base = THREAD_TABLE_START + tid * THREAD_ENTRY_SIZE

        # init thread-table for tid
        memory[base + 0] = tid
        memory[base + 1] = memory[REG_INSTR_COUNT]  # record start time
        memory[base + 2] = 0                         # reset per-thread count
        memory[base + 3] = 1                         # running
        memory[base + 4] = A                         # saved PC
        memory[base + 5] = memory[REG_SP]            # saved SP

        saved_kernel_pc = memory[REG_PC] + 1
        in_kernel      = False
        current_thread = tid
        memory[REG_PC] = A
        if DEBUG_MODE == 3:
            dump_thread_table()
        incr_instr_count()
        return

    # — SYSCALL_PRN A
    if op == "SYSCALL_PRN":
        (A,) = args
        print(memory[A])
        incr_instr_count(100)
        memory[REG_PC] += 1
        if DEBUG_MODE == 3:
            dump_thread_table()
        return

    # — SYSCALL_HLT: terminate thread or entire CPU if in kernel
    if op == "SYSCALL_HLT":
        # if we're in kernel, it's a real HLT
        if in_kernel:
            incr_instr_count()
            halted = True
            return

        # else terminate current thread
        base = THREAD_TABLE_START + current_thread * THREAD_ENTRY_SIZE
        memory[base + 3] = 2   # terminated

        # pick next thread
        nid = pick_next_thread(current_thread)
        if nid is None:
            incr_instr_count()
            halted = True
            return

        # restore next
        nbase = THREAD_TABLE_START + nid * THREAD_ENTRY_SIZE
        memory[REG_PC]    = memory[nbase + 4]
        memory[REG_SP]    = memory[nbase + 5]
        memory[nbase + 3] = 1   # running
        current_thread    = nid
        in_kernel         = False
        incr_instr_count()
        if DEBUG_MODE == 3:
            dump_thread_table()
        return

    # — SYSCALL_YIELD: voluntarily give up CPU
    if op == "SYSCALL_YIELD":
        base = THREAD_TABLE_START + current_thread * THREAD_ENTRY_SIZE
        memory[base + 4] = memory[REG_PC] + 1
        memory[base + 5] = memory[REG_SP]
        memory[base + 3] = 0   # back to ready

        # pick next
        nid = pick_next_thread(current_thread)
        if nid is None:
            incr_instr_count()
            halted = True
            return

        # restore next
        nbase = THREAD_TABLE_START + nid * THREAD_ENTRY_SIZE
        memory[REG_PC]    = memory[nbase + 4]
        memory[REG_SP]    = memory[nbase + 5]
        memory[nbase + 3] = 1
        current_thread    = nid
        in_kernel         = False
        incr_instr_count()
        if DEBUG_MODE == 3:
            dump_thread_table()
        return

    # — JIF A≤0 → PC=C
    if op == "JIF":
        A, C = args
        if memory[A] <= 0:
            memory[REG_PC] = C
            incr_instr_count()
            return

    # — by default advance PC
    memory[REG_PC] += 1
    incr_instr_count()


def load_program_from_file(fn):
    global instruction_list
    raw = open(fn, encoding='utf-8', errors='ignore').read().splitlines()
    # strip comments & blank lines
    lines = [l.split('#',1)[0].strip() for l in raw if l.strip() and not l.strip().startswith('#')]

    # Data section
    ds, de = lines.index("Begin Data Section"), lines.index("End Data Section")
    for ln in lines[ds+1:de]:
        a,b = ln.split()[:2]
        memory[int(a)] = int(b)

    # Instruction section
    is_, ie = lines.index("Begin Instruction Section"), lines.index("End Instruction Section")
    temp, maxpc = {}, -1
    for ln in lines[is_+1:ie]:
        p = ln.split()
        pc, op = int(p[0]), p[1]
        if op=="SYSCALL":
            typ = p[2]
            if typ=="PRN":
                instr = ("SYSCALL_PRN", int(p[3]))
            elif typ=="HLT":
                instr = ("SYSCALL_HLT",)
            else:
                instr = ("SYSCALL_YIELD",)
        else:
            instr = (op,) + tuple(int(x) for x in p[2:])
        temp[pc] = instr
        maxpc = max(maxpc, pc)

    # fill in
    instruction_list = [("HLT",)] * (maxpc+1)
    for pc, ins in temp.items():
        instruction_list[pc] = ins


def main():
    global DEBUG_MODE

    # ———— NEW: command-line parsing ————
    parser = argparse.ArgumentParser(
        description="GTU-C312 CPU simulator with cooperative threading"
    )
    parser.add_argument(
        "-D", type=int, choices=[0,1,2,3], default=-1,
        help="debug mode: 0=mem dump on halt, 1=mem dump after each instr, 2=step mode, 3=thread-table on ctxswitch/syscall"
    )
    parser.add_argument("program", help="input .cpu file")
    args = parser.parse_args()

    DEBUG_MODE = args.D

    load_program_from_file(args.program)

    # initialize PC, SP, INSTR_COUNT
    memory[REG_PC]          = 0
    memory[REG_SP]          = 0
    memory[REG_INSTR_COUNT] = 0

    # set up OS slot = tid 0
    os_base = THREAD_TABLE_START + 0*THREAD_ENTRY_SIZE
    memory[os_base + 0] = 0                         # tid
    memory[os_base + 1] = memory[REG_INSTR_COUNT]   # start_time
    memory[os_base + 2] = 0                         # used_instrs
    memory[os_base + 3] = 1                         # state = running
    memory[os_base + 4] = memory[REG_PC]            # saved PC
    memory[os_base + 5] = memory[REG_SP]            # saved SP

    global halted, in_kernel, current_thread
    halted          = False
    in_kernel       = True
    current_thread  = None

    while not halted:
        execute_one_instruction()

        # Debug mode 1: after each instruction
        if DEBUG_MODE == 1:
            dump_memory()
        # Debug mode 2: step mode: dump + wait for user to press Enter
        elif DEBUG_MODE == 2:
            dump_memory()
            input("Press Enter to execute next instruction...")
    # Debug mode 0: after halt
    if DEBUG_MODE == 0:
        dump_memory()

    print("SIMULATOR HALTED at PC =", memory[REG_PC])
    print("Instructions executed:", memory[REG_INSTR_COUNT])



if __name__ == "__main__":
    main()