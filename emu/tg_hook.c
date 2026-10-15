/* native translation-block hook: counts executed code bytes and asks Unicorn to stop when the budget is used up.
   (emu_start(count=N) flushes Unicorn's translation cache on every call, which made time-slicing 10x slower) */
#include <stdint.h>
typedef int (*stop_fn)(void *);
static stop_fn stopper;
static uint64_t used, budget = ~0ULL;
void tg_init(stop_fn f) { stopper = f; }
void tg_budget(uint64_t b) { used = 0; budget = b; }
uint64_t tg_used(void) { return used; }
void tg_blk(void *uc, uint64_t addr, uint32_t size, void *ud) {
    (void)addr; (void)ud;
    used += size;
    if (used >= budget) stopper(uc);
}
