idf_component_register(SRCS "configuration.c" "providore.c" "ota.c"
                    INCLUDE_DIRS "include"
                    PRIV_REQUIRES mbedtls esp_http_client app_update esp_common nvs_flash
                    )
