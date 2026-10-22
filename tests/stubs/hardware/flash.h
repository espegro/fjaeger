#pragma once
#include <stddef.h>
#include <stdint.h>
#define FLASH_SECTOR_SIZE 4096u
#define FLASH_PAGE_SIZE 256u
#define PICO_FLASH_SIZE_BYTES (2 * FLASH_SECTOR_SIZE)
extern uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
#define XIP_BASE ((uintptr_t)test_flash)
void flash_range_erase(uint32_t offset, size_t count);
void flash_range_program(uint32_t offset, const uint8_t *data, size_t count);
