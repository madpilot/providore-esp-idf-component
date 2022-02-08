#include "providore.h"
#include <string.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "esp_hmac.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "ota.h"
#include "types.h"

static const char *TAG = "PROVIDORE";

typedef struct _request_context
{
  char url[URL_BUFFER_LEN];
  char *response;
  size_t response_len;
  size_t response_max_len;
  char created_at[ISO8601_DATE_LEN];
  char expiry[ISO8601_DATE_LEN];
  char signature[SIGNATURE_LEN];
} request_context_t;

esp_err_t http_event_handle(esp_http_client_event_t *evt)
{
  switch (evt->event_id)
  {
  case HTTP_EVENT_ERROR:
    ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
    break;
  case HTTP_EVENT_ON_CONNECTED:
    break;
  case HTTP_EVENT_HEADER_SENT:
    break;
  case HTTP_EVENT_ON_HEADER:
  {
    request_context_t *context = (request_context_t *)evt->user_data;
    ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER: %s: %s", evt->header_key, evt->header_value);
    if (strncmp(evt->header_key, "created-at", 10) == 0)
    {
      strncpy(context->created_at, evt->header_value, ISO8601_DATE_LEN);
    }
    if (strncmp(evt->header_key, "expiry", 6) == 0)
    {
      strncpy(context->expiry, evt->header_value, ISO8601_DATE_LEN);
    }
    if (strncmp(evt->header_key, "signature", 9) == 0)
    {
      strncpy(context->signature, evt->header_value, SIGNATURE_LEN);
    }
  }
  break;
  case HTTP_EVENT_ON_DATA:
  {
    request_context_t *context = (request_context_t *)evt->user_data;
    if (context->response_len < context->response_max_len)
    {
      size_t len = context->response_len + evt->data_len > context->response_max_len ? context->response_max_len - context->response_len : evt->data_len;
      memcpy(context->response + context->response_len, evt->data, len);
      context->response_len += len;
    }
  }
  break;
  case HTTP_EVENT_ON_FINISH:
    break;
  case HTTP_EVENT_DISCONNECTED:
    break;
  }
  return ESP_OK;
}

void generate_hmac_signature(char *buffer, size_t buffer_len, const char *method, const char *path, const char *version, const char *created_at, const char *expiry)
{
  char *buffer_ptr = buffer;
  memset(buffer_ptr, 0, sizeof(char) * buffer_len);

  strcpy(buffer + strlen(buffer), method);
  strcpy(buffer + strlen(buffer), "\n");
  strcpy(buffer + strlen(buffer), path);
  strcpy(buffer + strlen(buffer), "\n");
  strcpy(buffer + strlen(buffer), version);
  strcpy(buffer + strlen(buffer), "\n");
  strcpy(buffer + strlen(buffer), created_at);
  strcpy(buffer + strlen(buffer), "\n");
  strcpy(buffer + strlen(buffer), expiry);
}

esp_err_t hmac_calculate(const char *psk, const void *message, size_t message_len, uint8_t *sig)
{
#ifdef SECURED_SHARED_KEY
  return esp_hmac_calculate(ETS_EFUSE_BLOCK_KEY4, (const void *)&message, strlen(message), (uint8_t *)&sig);
#else
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (unsigned char *)psk, strlen(psk));
  mbedtls_md_hmac_update(&ctx, (const unsigned char *)message, strlen(message));
  mbedtls_md_hmac_finish(&ctx, sig);
  return ESP_OK;
#endif
}

void generate_hmac(char *buffer, size_t buffer_len, const char *device_id, const char *psk, const char *method, const char *path, const char *version, const char *created_at, const char *expiry)
{
  char sig[32];
  char signature[buffer_len - 21];

  memset(buffer, 0, sizeof(char) * buffer_len);

  generate_hmac_signature((char *)&signature, buffer_len - 21, method, path, version, created_at, expiry);
  hmac_calculate(psk, (const void *)&signature, strlen(signature), (uint8_t *)&sig);

  char base64[48];
  size_t olen;
  mbedtls_base64_encode((unsigned char *)&base64, 48, &olen, (const unsigned char *)&sig, 32);
  strcpy(buffer, "Hmac key-id=");
  strcpy(buffer + strlen(buffer), device_id);
  strcpy(buffer + strlen(buffer), ", signature=");
  strcpy(buffer + strlen(buffer), base64);
}

bool verify_message(const char *psk, request_context_t *context)
{
  uint buffer_len = context->response_len + 1 + ISO8601_DATE_LEN + 1 + ISO8601_DATE_LEN + 1;
  char buffer[buffer_len];
  char sig[SIGNATURE_LEN];
  char base64[48];
  size_t olen;

  bzero(&buffer, buffer_len);
  snprintf((char *)buffer, buffer_len, "%s\n%s\n%s", context->response, context->created_at, context->expiry);
  hmac_calculate(psk, (char *)buffer, strlen(buffer), (uint8_t *)&sig);
  mbedtls_base64_encode((unsigned char *)&base64, 48, &olen, (const unsigned char *)&sig, 32);
  return strncmp((const char *)base64, context->signature, SIGNATURE_LEN) == 0;
}

void generate_iso8601_timestamp(time_t *time, char *output)
{
  // https: // stackoverflow.com/questions/10530804/gmtime-change-two-pointers-at-the-same-time
  struct tm input = *gmtime(time);
  memset(output, 0, sizeof(char) * ISO8601_DATE_LEN);
  strftime(output, ISO8601_DATE_LEN, "%FT%TZ", &input);
}

providore_err_t providore_get(const char *method, const char *path, const char *device_id, const char *psk, size_t output_max_len, const char *output, size_t *output_len)
{
  request_context_t context;

  bzero(output, output_max_len);
  bzero(&context, sizeof(context));

  time_t now = time(&now);
  time_t until = now + (15 * 60);

  char hmac[HMAC_BUFFER_LEN];
  const char created_at[ISO8601_DATE_LEN];
  const char expiry[ISO8601_DATE_LEN];

  char *url_ptr = (char *)&context.url;
  memset(url_ptr, 0, sizeof(char) * URL_BUFFER_LEN);
  strcpy(url_ptr, CONFIG_PROVIDORE_SERVER);
  strcpy(url_ptr + strlen((char *)&context.url), path);

  context.response = (char *)output;
  context.response_max_len = output_max_len;

  esp_http_client_config_t http_client_config = {
      .url = url_ptr,
      .event_handler = http_event_handle,
      .user_data = (void *)&context};

  generate_iso8601_timestamp(&now, (char *)&created_at);
  generate_iso8601_timestamp(&until, (char *)&expiry);
  generate_hmac((char *)&hmac, HMAC_BUFFER_LEN, device_id, psk, method, path, FIRMWARE_VERSION, (char *)&created_at, (char *)&expiry);

  esp_http_client_handle_t client = esp_http_client_init(&http_client_config);
  esp_http_client_set_header(client, "X-Firmware-Version", FIRMWARE_VERSION);
  esp_http_client_set_header(client, "Authorization", (const char *)&hmac);
  esp_http_client_set_header(client, "Created-At", (const char *)&created_at);
  esp_http_client_set_header(client, "Expiry", (const char *)&expiry);

  esp_err_t err = esp_http_client_perform(client);
  if (err != ESP_OK)
  {
    ESP_LOGE(TAG, "Fetch error");
  }

  esp_http_client_cleanup(client);
  if (verify_message(psk, &context))
  {
    return PROVIDORE_OK;
  }
  else
  {
    return PROVIDORE_SIG_MISMATCH;
  }
}

providore_err_t providore_get_config(const char *device_id, const char *psk, size_t output_max_len, const char *output, size_t *output_len)
{
  return providore_get("GET", "/config", device_id, psk, output_max_len, output, output_len);
}

void providore_firmware_upgrade_task(void *arguments)
{
  ota_request_context_t *context = (ota_request_context_t *)arguments;
  time_t now = time(&now);
  time_t until = now + (15 * 60);

  char hmac[HMAC_BUFFER_LEN];
  const char created_at[ISO8601_DATE_LEN];
  const char expiry[ISO8601_DATE_LEN];

  char *url_ptr = (char *)&(context->url);
  memset(url_ptr, 0, sizeof(char) * URL_BUFFER_LEN);
  strcpy(url_ptr, CONFIG_PROVIDORE_SERVER);
  strcpy(url_ptr + strlen((char *)&(context->url)), "/firmware");

  esp_http_client_config_t http_client_config = {
      .url = url_ptr,
      .event_handler = providore_ota_firmware_event_handle,
      .user_data = context};

  generate_iso8601_timestamp(&now, (char *)&created_at);
  generate_iso8601_timestamp(&until, (char *)&expiry);
  generate_hmac((char *)&hmac, HMAC_BUFFER_LEN, context->device_id, context->psk, "GET", "/firmware", FIRMWARE_VERSION, (char *)&created_at, (char *)&expiry);

  esp_http_client_handle_t client = esp_http_client_init(&http_client_config);
  esp_http_client_set_header(client, "X-Firmware-Version", FIRMWARE_VERSION);
  esp_http_client_set_header(client, "Authorization", (const char *)&hmac);
  esp_http_client_set_header(client, "Created-At", (const char *)&created_at);
  esp_http_client_set_header(client, "Expiry", (const char *)&expiry);

  esp_err_t err = esp_http_client_perform(client);
  if (err != ESP_OK)
  {
    ESP_LOGE(TAG, "Fetch error %i", err);
  }

  esp_http_client_cleanup(client);
  vTaskDelete(NULL);
}

ota_request_context_t context;
providore_err_t providore_firmware_upgrade(const char *device_id, const char *psk)
{
  TaskHandle_t handle;
  bzero(&context, sizeof(context));
  context.ota_state = OTA_READY;
  context.device_id = device_id;
  context.psk = psk;
  context.event_group = xEventGroupCreate();

  xTaskCreate(providore_firmware_upgrade_task, "firmware_upgrade", 8096, (void *)&context, 1, &handle);
  EventBits_t result = xEventGroupWaitBits(context.event_group, OTA_COMPLETED | OTA_FAILED, pdFALSE, pdFALSE, portMAX_DELAY);
  if (result == OTA_COMPLETED)
  {
    return PROVIDORE_OK;
  }

  return PROVIDORE_FIRMWARE_FAIL;
}

bool providore_self_test_required()
{
  esp_ota_img_states_t state;
  esp_partition_t *partition = esp_ota_get_running_partition();
  esp_err_t result = esp_ota_get_state_partition(partition, &state);
  if (result != ESP_OK)
  {
    switch (result)
    {
    case ESP_ERR_INVALID_ARG:
      ESP_LOGE(TAG, "Partition on state argument was NULL");
      return false;
    case ESP_ERR_NOT_SUPPORTED:
      ESP_LOGW(TAG, "Partition is not an OTA partition");
      return false;
    case ESP_ERR_NOT_FOUND:
      ESP_LOGW(TAG, "Partition table does not have otadata or state was not found for given partition");
      return false;
    }
  }
  return state == ESP_OTA_IMG_PENDING_VERIFY;
}

void providore_confirm_upgrade()
{
  ESP_LOGI(TAG, "Confirming the last firmware update.");
  esp_ota_mark_app_valid_cancel_rollback();
}

void providore_rollback_upgrade()
{
  ESP_LOGI(TAG, "Rolling back the last firmware update.");
  esp_ota_mark_app_invalid_rollback_and_reboot();
}