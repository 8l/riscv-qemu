#if !defined (__RISCV_CPU_H__)
#define __RISCV_CPU_H__

//#define DEBUG_OP

#define TARGET_HAS_ICE 1

#define ELF_MACHINE	EM_RISCV

#define CPUArchState struct CPURISCVState

#define RISCV_START_PC 0x2000

#include "config.h"
#include "qemu-common.h"
#include "riscv-defs.h"
#include "exec/cpu-defs.h"

#define NB_MMU_MODES 2

struct CPURISCVState;

// user new csrs
#define csr_fflags   0x001
#define csr_frm      0x002
#define csr_fcsr     0x003
#define csr_cycle    0xc00
#define csr_time     0xc01
#define csr_instret  0xc02
#define csr_cycleh   0xc80
#define csr_timeh    0xc81
#define csr_instreth 0xc82


// supervisor new csrs
#define csr_sstatus   0x100
#define csr_stvec     0x101
#define csr_sie       0x104
#define csr_stimecmp  0x121
#define csr_stime     0xd01
#define csr_stimeh    0xd81
#define csr_sscratch  0x140
#define csr_sepc      0x141
#define csr_scause    0xd42
#define csr_sbadaddr  0xd43
#define csr_sip       0x144
#define csr_sptbr     0x180
#define csr_sasid     0x181
#define csr_cyclew    0x900
#define csr_timew     0x901
#define csr_instretw  0x902
#define csr_cyclehw   0x980
#define csr_timehw    0x981
#define csr_instrethw 0x982

// RISCV Exception Codes
#define EXCP_NONE                       -1   // not a real RISCV exception code
#define RISCV_EXCP_INST_ADDR_MIS        0x0
#define RISCV_EXCP_INST_ACCESS_FAULT    0x1
#define RISCV_EXCP_ILLEGAL_INST         0x2
#define RISCV_EXCP_BREAKPOINT           0x3
#define RISCV_EXCP_LOAD_ADDR_MIS        0x4
#define RISCV_EXCP_LOAD_ACCESS_FAULT    0x5
#define RISCV_EXCP_STORE_ADDR_MIS       0x6
#define RISCV_EXCP_STORE_ACCESS_FAULT   0x7
#define RISCV_EXCP_ECALL_U              0x8
#define RISCV_EXCP_ECALL_S              0x9
#define RISCV_EXCP_ECALL_H              0xa
#define RISCV_EXCP_ECALL_M              0xb

// Interrupts
#define RISCV_EXCP_SOFT_INTERRUPT       (0x0 | (1 << 31)) 
#define RISCV_EXCP_TIMER_INTERRUPT      (0x1 | (1 << 31)) 

// RISCV Status Reg Bits
#define SR_S           0x1
#define SR_PS          0x2
#define SR_EI          0x4
#define SR_PEI         0x8
#define SR_EF         0x10
#define SR_U64        0x20
#define SR_S64        0x40
#define SR_VM         0x80
#define SR_EA        0x100
#define SR_IM     0xFF0000
#define SR_IP   0xFF000000

// RISCV pte bits
#define PTE_V    0x1
#define PTE_T    0x2
#define PTE_G    0x4
#define PTE_UR   0x8
#define PTE_UW  0x10
#define PTE_UX  0x20
#define PTE_SR  0x40
#define PTE_SW  0x80
#define PTE_SX 0x100

typedef struct riscv_def_t riscv_def_t;

typedef struct TCState TCState;
struct TCState {
    target_ulong gpr[32];
    target_ulong fpr[32];
    target_ulong PC;
};

typedef struct CPURISCVState CPURISCVState;
struct CPURISCVState {
    TCState active_tc;
    uint32_t current_tc;
    uint32_t SEGBITS;
    uint32_t PABITS;
    target_ulong SEGMask;
    target_ulong PAMask;

    uint64_t helper_csr[4096]; // RISCV CSR registers

    /* QEMU */
    CPU_COMMON

    /* Fields from here on are preserved across CPU reset. */
    const riscv_def_t *cpu_model;
    void *irq[8];
    QEMUTimer *timer; /* Internal timer */
};

#include "cpu-qom.h"

#if !defined(CONFIG_USER_ONLY)
void riscv_cpu_unassigned_access(CPUState *cpu, hwaddr addr,
                                bool is_write, bool is_exec, int unused,
                                unsigned size);
#endif

void riscv_cpu_list (FILE *f, fprintf_function cpu_fprintf);

#define cpu_exec cpu_riscv_exec
#define cpu_gen_code cpu_riscv_gen_code
#define cpu_signal_handler cpu_riscv_signal_handler
#define cpu_list riscv_cpu_list

extern void cpu_wrdsp(uint32_t rs, uint32_t mask_num, CPURISCVState *env);
extern uint32_t cpu_rddsp(uint32_t mask_num, CPURISCVState *env);

#define CPU_SAVE_VERSION 3

static inline int cpu_mmu_index (CPURISCVState *env)
{
    return env->helper_csr[CSR_STATUS] & SR_S;
}

static inline int cpu_riscv_hw_interrupts_pending(CPURISCVState *env)
{
    int32_t pending;
    int32_t status;
    int r;

    /* first check if interrupts are disabled */
    if (!((env->helper_csr[CSR_STATUS] >> 2) & 0x1)) {
        // interrupts disabled
        return 0;
    }

    pending = (env->helper_csr[CSR_STATUS] >> 24) & 0xFF;
    status = (env->helper_csr[CSR_STATUS] >> 16) & 0xFF;

    r = pending & status;
    return r;
}

#include "exec/cpu-all.h"

/* Memory access type :
 * may be needed for precise access rights control and precise exceptions.
 */
enum {
    /* 1 bit to define user level / supervisor access */
    ACCESS_USER  = 0x00,
    ACCESS_SUPER = 0x01,
    /* 1 bit to indicate direction */
    ACCESS_STORE = 0x02,
    /* Type of instruction that generated the access */
    ACCESS_CODE  = 0x10, /* Code fetch access                */
    ACCESS_INT   = 0x20, /* Integer load/store access        */
    ACCESS_FLOAT = 0x30, /* floating point load/store access */
};

int cpu_riscv_exec(CPURISCVState *s);
void riscv_tcg_init(void);
RISCVCPU *cpu_riscv_init(const char *cpu_model);
int cpu_riscv_signal_handler(int host_signum, void *pinfo, void *puc);

static inline CPURISCVState *cpu_init(const char *cpu_model)
{
    RISCVCPU *cpu = cpu_riscv_init(cpu_model);
    if (cpu == NULL) {
        return NULL;
    }
    return &cpu->env;
}

/* TODO QOM'ify CPU reset and remove */
void cpu_state_reset(CPURISCVState *s);

/* hw/riscv/cputimer.c */
uint64_t cpu_riscv_get_cycle (CPURISCVState *env);
uint32_t cpu_riscv_get_random (CPURISCVState *env);
uint32_t cpu_riscv_get_count (CPURISCVState *env);
void cpu_riscv_store_count (CPURISCVState *env, uint32_t value);
void cpu_riscv_store_compare (CPURISCVState *env, uint32_t value);
void cpu_riscv_start_count(CPURISCVState *env);

/* hw/riscv/riscv_int.c */
void cpu_riscv_soft_irq(CPURISCVState *env, int irq, int level);

/* helper.c */
int riscv_cpu_handle_mmu_fault(CPUState *cpu, vaddr address, int rw,
                              int mmu_idx);
#if !defined(CONFIG_USER_ONLY)
hwaddr cpu_riscv_translate_address (CPURISCVState *env, target_ulong address,
		                               int rw);
#endif

static inline void cpu_get_tb_cpu_state(CPURISCVState *env, target_ulong *pc,
                                        target_ulong *cs_base, int *flags)
{
    *pc = env->active_tc.PC;
    *cs_base = 0;
    *flags = 0; // necessary to avoid compiler warning
}

#include "exec/exec-all.h"

#endif /* !defined (__RISCV_CPU_H__) */
