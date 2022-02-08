#include "ota.h"
#include "esp_ota_ops.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include <string.h>
#include "types.h"
#include "esp_task_wdt.h"

static const char *TAG = "PROVIDORE_OTA";

esp_err_t providore_ota_firmware_event_handle(esp_http_client_event_t *evt)
{
  ota_request_context_t *context = (ota_request_context_t *)evt->user_data;
  switch (evt->event_id)
  {
  case HTTP_EVENT_ERROR:
    context->ota_state = OTA_FAILED;
    ESP_LOGE(TAG, "OTA Failed: HTTP Error");
    break;
  case HTTP_EVENT_ON_CONNECTED:
  {
    esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
    esp_err_t res = esp_ota_begin(partition, OTA_SIZE_UNKNOWN, &(context->ota_handle));
    switch (res)
    {
    case ESP_OK:
      context->ota_state = OTA_WAITING;
      ESP_LOGI(TAG, "Starting OTA...");
      break;
    case ESP_ERR_INVALID_ARG:
      context->ota_state = OTA_ERROR;
      ESP_LOGE(TAG, "Error starting OTA: Partition or Handle is NULL, or partition doesn't point to an OTA app partition.");
      break;
    case ESP_ERR_NO_MEM:
      context->ota_state = OTA_ERROR;
      ESP_LOGE(TAG, "Error starting OTA: Cannot allocate memory for OTA operation.");
      break;
    case ESP_ERR_OTA_PARTITION_CONFLICT:
      context->ota_state = OTA_ERROR;
      ESP_LOGE(TAG, "Error starting OTA: Partition holds the currently running firmware, cannot update in place.");
      break;
    case ESP_ERR_NOT_FOUND:
      context->ota_state = OTA_ERROR;
      ESP_LOGE(TAG, "Error starting OTA: Partition argument not found in partition table.");
      break;
    case ESP_ERR_OTA_SELECT_INFO_INVALID:
      context->ota_state = OTA_ERROR;
      ESP_LOGE(TAG, "Error starting OTA: The OTA data partition contains invalid data.");
      break;
    case ESP_ERR_INVALID_SIZE:
      context->ota_state = OTA_ERROR;
      ESP_LOGE(TAG, "Error starting OTA: Partition doesn't fit in configured flash size");
      break;
    case ESP_ERR_FLASH_OP_TIMEOUT:
      context->ota_state = OTA_ERROR;
      ESP_LOGE(TAG, "Error starting OTA: Error starting OTA: Flash write timed out.");
      break;
    case ESP_ERR_FLASH_OP_FAIL:
      context->ota_state = OTA_ERROR;
      ESP_LOGE(TAG, "Error starting OTA: Error starting OTA: Flash write failed.");
      break;
    }
  }
  break;
  case HTTP_EVENT_HEADER_SENT:
    break;
  case HTTP_EVENT_ON_HEADER:
    break;
  case HTTP_EVENT_ON_DATA:
  {
    // This can get CPU heavy - feed the watchdog.
    esp_task_wdt_reset();

    if (context->ota_state == OTA_WAITING)
    {
      context->ota_state = OTA_IN_PROGRESS;
    }

    if (context->ota_state == OTA_IN_PROGRESS)
    {
      esp_err_t result = esp_ota_write(context->ota_handle, evt->data, evt->data_len);
      switch (result)
      {
      case ESP_OK:
        context->downloaded += evt->data_len;
        ESP_LOGI(TAG, "Written %i bytes", context->downloaded);
        break;
      case ESP_ERR_INVALID_ARG:
        context->ota_state = OTA_ERROR;
        ESP_LOGE(TAG, "OTA error writing to partition: Invalid Argument");
        break;
      case ESP_ERR_OTA_VALIDATE_FAILED:
        context->ota_state = OTA_ERROR;
        ESP_LOGE(TAG, "OTA error writing to partition: Handle is invalid");
        break;
      case ESP_ERR_FLASH_OP_TIMEOUT:
        context->ota_state = OTA_ERROR;
        ESP_LOGE(TAG, "OTA error writing to partition: Flash write timed out");
        break;
      case ESP_ERR_FLASH_OP_FAIL:
        context->ota_state = OTA_ERROR;
        ESP_LOGE(TAG, "OTA error writing to partition: Flash write failed");
        break;
      case ESP_ERR_OTA_SELECT_INFO_INVALID:
        context->ota_state = OTA_ERROR;
        ESP_LOGE(TAG, "OTA error writing to partition: OTA data partition has invalid contents");
      }
    }
  }
  break;
  case HTTP_EVENT_ON_FINISH:
  {
    if (context->ota_state == OTA_IN_PROGRESS)
    {
      context->ota_state = OTA_COMPLETED;
    }
    else
    {
      context->ota_state = OTA_FAILED;
    }

    if (context->ota_state == OTA_COMPLETED)
    {
      ESP_LOGI(TAG, "OTA finished");
      esp_err_t result = esp_ota_end(context->ota_handle);

      if (result == ESP_OK)
      {
        ESP_LOGI(TAG, "OTA complete");
        esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
        result = esp_ota_set_boot_partition(partition);
        if (result != ESP_OK)
        {
          context->ota_state = OTA_FAILED;
        }
      }
      else
      {
        switch (result)
        {
        case ESP_ERR_INVALID_ARG:
          ESP_LOGE(TAG, "Invalid Argument");
          break;
        case ESP_ERR_OTA_VALIDATE_FAILED:
          ESP_LOGE(TAG, "OTA failed to end: First byte of image contains invalid app image magicbyte.");
          break;
        case ESP_ERR_OTA_SELECT_INFO_INVALID:
          ESP_LOGE(TAG, "OTA failed to end: OTA data partition has invalid contents");
          break;
        case ESP_ERR_FLASH_OP_TIMEOUT:
          ESP_LOGE(TAG, "OTA failed to end: Flash write failed (timeout)");
          break;
        case ESP_ERR_FLASH_OP_FAIL:
          ESP_LOGE(TAG, "OTA failed to end: Flash write failed");
          break;
        }
        context->ota_state = OTA_FAILED;
      }
    }
  }
  break;
  case HTTP_EVENT_DISCONNECTED:
  {
    if (context->ota_state != OTA_COMPLETED && context->ota_state != OTA_FAILED)
    {
      if (context->ota_state == OTA_READY)
      {
        ESP_LOGE(TAG, "OTA failed - connection closed before OTA started.");
      }
      if (context->ota_state == OTA_WAITING)
      {
        ESP_LOGE(TAG, "OTA failed - connection closed before OTA download started.");
      }
      if (context->ota_state == OTA_IN_PROGRESS)
      {
        ESP_LOGE(TAG, "OTA failed - connection closed before OTA while downloading.");
      }
      if (context->ota_state == OTA_ERROR)
      {
        ESP_LOGE(TAG, "OTA failed - server disconnected.");
      }
      context->ota_state = OTA_FAILED;
    }
  }
  break;
  }

  if (context->ota_state == OTA_COMPLETED)
  {
    xEventGroupSetBits(context->event_group, OTA_COMPLETED);
  }
  else if (context->ota_state == OTA_FAILED)
  {
    if (context->ota_handle)
    {
      esp_ota_abort(context->ota_handle);
    }
    xEventGroupSetBits(context->event_group, OTA_FAILED);
  }
  return ESP_OK;
}
