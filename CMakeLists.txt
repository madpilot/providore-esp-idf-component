idf_component_register(SRCS "providore.c" "ota.c"
                    INCLUDE_DIRS "include"
                    PRIV_REQUIRES mbedtls esp_http_client app_update esp_common
                    )
