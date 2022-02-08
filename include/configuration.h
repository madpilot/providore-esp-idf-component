#ifndef _PROVIDORE_CONFIGURATION_h
#define _PROVIDORE_CONFIGURATION_h
#include <stdbool.h>
#include <esp_err.h>

// Check to see if all the configuration options that are set
esp_err_t get_device_id(char *out_value, size_t *length);
esp_err_t get_psk(char *out_value, size_t *length);
bool providore_check_configuration();
#endif