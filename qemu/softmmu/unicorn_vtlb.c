#include <stdint.h>
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/exec-all.h"
#include "uc_priv.h"

#include <stdio.h>

static void raise_mmu_exception(CPUState *cs, target_ulong address,
                                int rw, uintptr_t retaddr)
{
    switch (rw) {
    case MMU_DATA_LOAD:
        cs->uc->invalid_error = UC_ERR_MMU_READ;
        break;
    case MMU_DATA_STORE:
        cs->uc->invalid_error = UC_ERR_MMU_WRITE;
        break;
    case MMU_INST_FETCH:
        cs->uc->invalid_error = UC_ERR_MMU_FETCH;
        break;
    default:
        cs->uc->invalid_error = UC_ERR_MMU_READ;
    }
    cs->uc->invalid_addr = address;
    cpu_exit(cs->uc->cpu);
    cpu_loop_exit_restore(cs, retaddr);
}

static uc_mem_type rw_to_mem_type(int rw)
{
    switch (rw) {
    case MMU_DATA_LOAD:
        return UC_MEM_READ;
    case MMU_DATA_STORE:
        return UC_MEM_WRITE;
    case MMU_INST_FETCH:
        return UC_MEM_FETCH;
    default:
        return UC_MEM_READ;
    }
}

static int perms_to_prot(int perms)
{
    int ret = 0;
    if (perms & UC_PROT_READ) {
        ret |= PAGE_READ;
    }
    if (perms & UC_PROT_WRITE) {
        ret |= PAGE_WRITE;
    }
    if (perms & UC_PROT_EXEC) {
        ret |= PAGE_EXEC;
    }
    return ret;
}

bool unicorn_fill_tlb(CPUState *cs, vaddr address, int size,
                      MMUAccessType rw, int mmu_idx,
                      bool probe, uintptr_t retaddr)
{
    bool handled = false;
    bool ret = false;
    struct uc_struct *uc = cs->uc;
    uc_tlb_entry e;
    struct hook *hook;
    bool sync_state = !uc->tlb_fill_fast;
    HOOK_FOREACH_VAR_DECLARE;

#if defined(TARGET_MIPS) || defined(TARGET_MIPS64)
    CPUMIPSState *mips_env = cs->env_ptr;
    uint32_t mips_branch_hflags;
    target_ulong mips_btarget;
#endif

    /* Standard hooks expose synchronized register state to callbacks. Fast
     * mode opts out of that work, so callbacks must not read registers.
     * Failed fills restore state in raise_mmu_exception before they exit the
     * CPU loop. */
    if (sync_state) {
#if defined(TARGET_MIPS) || defined(TARGET_MIPS64)
        mips_branch_hflags = mips_env->hflags & MIPS_HFLAG_BMASK;
        mips_btarget = mips_env->btarget;
#endif
        cpu_restore_state(cs, retaddr, false);
    }

    HOOK_FOREACH(uc, hook, UC_HOOK_TLB_FILL) {
        if (hook->to_delete) {
            continue;
        }
        if (!HOOK_BOUND_CHECK(hook, address)) {
            continue;
        }
        handled = true;
        JIT_CALLBACK_GUARD_VAR(ret, ((uc_cb_tlbevent_t)hook->callback)(uc, address & TARGET_PAGE_MASK, rw_to_mem_type(rw), &e, hook->user_data));
        if (ret) {
            break;
        }
    }

    if (handled && !ret) {
        goto tlb_miss;
    }

    if (!handled) {
        e.paddr = address & TARGET_PAGE_MASK;
        switch (rw) {
        case MMU_DATA_LOAD:
            e.perms = UC_PROT_READ;
            break;
        case MMU_DATA_STORE:
            e.perms = UC_PROT_WRITE;
            break;
        case MMU_INST_FETCH:
            e.perms = UC_PROT_EXEC;
            break;
        default:
            e.perms = 0;
            break;
        }
    }

    switch (rw) {
    case MMU_DATA_LOAD:
        ret = e.perms & UC_PROT_READ;
        break;
    case MMU_DATA_STORE:
        ret = e.perms & UC_PROT_WRITE;
        break;
    case MMU_INST_FETCH:
        ret = e.perms & UC_PROT_EXEC;
        break;
    default:
        ret = false;
        break;
    }

    if (ret) {
#if defined(TARGET_MIPS) || defined(TARGET_MIPS64)
        if (sync_state) {
            mips_env->hflags = (mips_env->hflags & ~MIPS_HFLAG_BMASK) |
                              mips_branch_hflags;
            mips_env->btarget = mips_btarget;
        }
#endif
        tlb_set_page(cs, address & TARGET_PAGE_MASK, e.paddr & TARGET_PAGE_MASK, perms_to_prot(e.perms), mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }

tlb_miss:
    if (probe) {
        return false;
    }
    raise_mmu_exception(cs, address, rw, retaddr);
    return false;
}
