#ifndef FJ_KEYS_STAGE_INTERNAL_H
#define FJ_KEYS_STAGE_INTERNAL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "restore_journal.h"

/* Only the staging implementation should consume these raw store images. */
bool fj_keys_stage_image(uint8_t *out, size_t capacity, size_t *length,
                         const fj_restore_plan_t *plan);
bool fj_keys_stage_image_valid(const void *image, size_t length, uint32_t generation);
bool fj_keys_stage_activate_image(const void *image, size_t length,
                                  const fj_restore_plan_t *plan);
bool fj_keys_restore_old_active(const fj_restore_plan_t *plan);
bool fj_keys_stage_image_active(const void *image, size_t length,
                                const fj_restore_plan_t *plan);
bool fj_keys_restore_copy_active(uint8_t *out, size_t capacity, size_t *length,
                                 uint32_t generation);
/* Internal primitive: caller verifies the selected image and journal first. */
bool fj_keys_restore_erase_inactive(uint32_t generation);
bool fj_keys_restore_staging_generation(uint32_t *generation);
bool fj_keys_restore_begin_transaction(void);
#endif
