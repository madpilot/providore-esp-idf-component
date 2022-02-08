#ifndef _PROVIDORE_h
#define _PROVIDORE_h
#include <string.h>
#include "error.h"
#include <stdbool.h>

void providore_confirm_upgrade();
providore_err_t providore_get_config(const char *device_id, const char *psk, size_t output_max_len, const char *output, size_t *output_len);
providore_err_t providore_firmware_upgrade(const char *device_id, const char *psk);

bool providore_self_test_required();
void providore_confirm_upgrade();
void providore_rollback_upgrade();
#endif