#include "exec/def-helper.h"

DEF_HELPER_3(raise_exception_err, noreturn, env, i32, int)
DEF_HELPER_2(raise_exception, noreturn, env, i32)

// TODO look at these for ll/sc
#ifndef CONFIG_USER_ONLY
DEF_HELPER_3(ll, tl, env, tl, int)
DEF_HELPER_4(sc, tl, env, tl, tl, int)
#ifdef TARGET_MIPS64
DEF_HELPER_3(lld, tl, env, tl, int)
DEF_HELPER_4(scd, tl, env, tl, tl, int)
#endif
#endif

DEF_HELPER_3(mulsu, tl, env, tl, tl)

/* Special functions */
#ifndef CONFIG_USER_ONLY
DEF_HELPER_1(tlbwi, void, env)
DEF_HELPER_1(tlbwr, void, env)
DEF_HELPER_1(tlbp, void, env)
DEF_HELPER_1(tlbr, void, env)
DEF_HELPER_1(di, tl, env)
DEF_HELPER_1(ei, tl, env)
DEF_HELPER_1(eret, void, env)
DEF_HELPER_1(deret, void, env)
#endif /* !CONFIG_USER_ONLY */
DEF_HELPER_1(rdhwr_cpunum, tl, env)
DEF_HELPER_1(rdhwr_synci_step, tl, env)
DEF_HELPER_1(rdhwr_cc, tl, env)
DEF_HELPER_1(rdhwr_ccres, tl, env)
DEF_HELPER_2(pmon, void, env, int)
DEF_HELPER_1(wait, void, env)


#include "exec/def-helper.h"
