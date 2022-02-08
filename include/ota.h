#ifndef _PROVIDORE_OTA_h
#define _PROVIDORE_OTA_h
#include "esp_err.h"
#include "esp_http_client.h"
#include "error.h"

esp_err_t providore_ota_firmware_event_handle(esp_http_client_event_t *evt);
#endif