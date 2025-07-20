if op == "SYSCALL_PRN":
    (A,) = args
    # 1) do the print
    print(memory[A])
    # 2) consume the syscall instruction
    incr_instr_count()
    memory[REG_PC] += 1

    # 3) block the current thread for 100 instructions
    base = THREAD_TABLE_START + current_thread * THREAD_ENTRY_SIZE
    memory[base + 3] = STATE_BLOCKED
    memory[87 + current_thread] = 100

    # 4) pick and switch to the next READY thread immediately
    nid = pick_next_thread(current_thread)
    if nid is None:
        halted = True
        return
    nbase = THREAD_TABLE_START + nid * THREAD_ENTRY_SIZE
    memory[REG_PC]    = memory[nbase + 4]
    memory[REG_SP]    = memory[nbase + 5]
    memory[nbase + 3] = STATE_RUNNING
    current_thread    = nid
    in_kernel         = False
    return