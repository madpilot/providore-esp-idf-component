#ifndef _PROVIDORE_TYPES_h
#define _PROVIDORE_TYPES_h

#include "esp_ota_ops.h"
#include "freertos/event_groups.h"

#define ISO8601_DATE_LEN 21
#define HMAC_BUFFER_LEN 128
#define URL_BUFFER_LEN 128
#define SIGNATURE_LEN 256
#define RESPONSE_BUFFER 1024
#define FIRMWARE_VERSION "1.0.0"

typedef enum _ota_state
{
  OTA_READY = 1 << 0,
  OTA_WAITING = 1 << 1,
  OTA_IN_PROGRESS = 1 << 2,
  OTA_COMPLETED = 1 << 3,
  OTA_ERROR = 1 << 4,
  OTA_FAILED = 1 << 5,
} ota_state_t;

typedef struct _ota_request_context
{
  char url[URL_BUFFER_LEN];
  char created_at[ISO8601_DATE_LEN];
  char expiry[ISO8601_DATE_LEN];
  char signature[SIGNATURE_LEN];
  char *device_id;
  EventGroupHandle_t event_group;
  esp_ota_handle_t ota_handle;
  ota_state_t ota_state;
  size_t downloaded;
} ota_request_context_t;
#endif