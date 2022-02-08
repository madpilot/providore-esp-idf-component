#include "configuration.h"
#include "nvs_flash.h"
#include "esp_log.h"

const char *TAG = "configuration";

esp_err_t get_device_id(char *out_value, size_t *length)
{
  nvs_handle_t handle;
  esp_err_t result = nvs_open("providore", NVS_READONLY, &handle);
  if (result != ESP_OK)
  {
    return result;
  }
  return nvs_get_str(handle, "device_id", out_value, length);
}

esp_err_t get_psk(char *out_value, size_t *length)
{
#ifdef CONFIG_SECURED_SHARED_KEY
  // If CONFIG_SECURED_SHARED_KEY is set, then the psk is never stored in NVS
  out_value = NULL;
  *length = 0;
  return ESP_OK;
#else
  nvs_handle_t handle;
  esp_err_t result = nvs_open("providore", NVS_READONLY, &handle);
  if (result != ESP_OK)
  {
    return result;
  }
  return nvs_get_str(handle, "psk", out_value, length);
#endif
}

bool providore_check_configuration()
{
  // Minimum configuration for providore stored in NVS:
  // 1. WIFI SSID
  // 2. WIFI Passkey
  // 3. Device ID
  //
  // if CONFIG_SECURED_SHARED_KEY is true: Check the shared key is in in KEY 4 of the eFuse
  // else: Check the shared key is in NVS

  // Check the Device ID
  nvs_handle_t handle;
  esp_err_t result = nvs_open("providore", NVS_READONLY, &handle);
  if (result != ESP_OK)
  {
    switch (result)
    {
    case ESP_ERR_NVS_NOT_INITIALIZED:
      ESP_LOGE(TAG, "NVS Error: NVS not initialized.");
      break;
    case ESP_ERR_NVS_PART_NOT_FOUND:
      ESP_LOGE(TAG, "NVS Error: NVS Partition not found. Have you set NVS yet?");
      break;
    case ESP_ERR_NVS_NOT_FOUND:
      ESP_LOGE(TAG, "NVS Error: Namespace not found. Have you set NVS yet?");
      break;
    case ESP_ERR_NVS_INVALID_NAME:
      ESP_LOGE(TAG, "NVS Error: Invalid namespace");
      break;
    case ESP_ERR_NO_MEM:
      ESP_LOGE(TAG, "NVS Error: Unable to allocate memory");
      break;
    default:
      ESP_LOGE(TAG, "NVS Error: Underlying storage error");
    }
    return false;
  }

  char out_value[64];
  size_t length;

  result = nvs_get_str(handle, "device_id", (char *)&out_value, &length);
  if (result != ESP_OK)
  {
    switch (result)
    {
    case ESP_ERR_NVS_NOT_FOUND:
      ESP_LOGE(TAG, "NVS Error: device_id not found");
      break;
    case ESP_ERR_NVS_INVALID_HANDLE:
      ESP_LOGE(TAG, "NVS Error: Handle has already been closed");
      break;
    case ESP_ERR_NVS_INVALID_NAME:
      ESP_LOGE(TAG, "NVS Error: device_id is not a valid NVS name");
      break;
    case ESP_ERR_NVS_INVALID_LENGTH:
      ESP_LOGE(TAG, "NVS Error: length variable not long enough to store data");
      break;
    }
  }

#ifdef CONFIG_SECURED_SHARED_KEY
  // TODO: Check efuse for key
#else
  result = nvs_get_str(handle, "psk", (char *)&out_value, &length);
  if (result != ESP_OK)
  {
    switch (result)
    {
    case ESP_ERR_NVS_NOT_FOUND:
      ESP_LOGE(TAG, "NVS Error: psk not found");
      break;
    case ESP_ERR_NVS_INVALID_HANDLE:
      ESP_LOGE(TAG, "NVS Error: Handle has already been closed");
      break;
    case ESP_ERR_NVS_INVALID_NAME:
      ESP_LOGE(TAG, "NVS Error: psk is not a valid NVS name");
      break;
    case ESP_ERR_NVS_INVALID_LENGTH:
      ESP_LOGE(TAG, "NVS Error: length variable not long enough to store data");
      break;
    }

    nvs_close(handle);
    return false;
  }
#endif

  nvs_close(handle);
  return true;
}