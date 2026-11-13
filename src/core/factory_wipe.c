#include "factory_wipe.h"
#include "flash_layout.h"
#include "restore_journal.h"
#include "hardware/sync.h"
#include <stddef.h>
#include <stdint.h>

static bool erase_region(uint32_t offset,size_t length) {
    const uint8_t *p=(const void *)(XIP_BASE+offset);
    for (size_t i=0;i<length;i++) {
        if (p[i]!=0xff) {
            uint32_t ints=save_and_disable_interrupts();
            flash_range_erase(offset,length);
            restore_interrupts(ints);
            for (size_t j=0;j<length;j++) if (p[j]!=0xff) return false;
            break;
        }
    }
    return true;
}
bool fj_factory_wipe_recover(void) {
    fj_restore_phase_t phase; fj_restore_plan_t plan;
    if (!fj_restore_journal_read(&phase,&plan) || phase!=FJ_RESTORE_WIPING) return false;
    /* Never erase the journal until all secret-bearing areas are verified.
     * Each operation is repeatable after power loss. */
    if (!erase_region(FJ_HMAC_CONFIG_OFFSET,2u*FLASH_SECTOR_SIZE) ||
        !erase_region(FJ_KEYS_STAGE_OFFSET,FJ_KEYS_SLOT_SIZE) ||
        !erase_region(FJ_HMAC_STAGE_OFFSET,FLASH_SECTOR_SIZE) ||
        !erase_region(FJ_HMAC_STORE_OFFSET,2u*FLASH_SECTOR_SIZE) ||
        !erase_region(FJ_KEYS_STORE_OFFSET,2u*FJ_KEYS_SLOT_SIZE+2u*FLASH_SECTOR_SIZE)) return false;
    return fj_restore_journal_finish_wipe();
}
bool fj_factory_wipe_start(void) {
    return fj_restore_journal_begin_wipe() && fj_factory_wipe_recover();
}
_Noreturn void fj_factory_wipe_halt(void) {
    /* No USB task or credential service runs until a physical reset; boot
     * will resume a durable WIPING decision or fail closed on bad journal. */
    for (;;) { }
}
