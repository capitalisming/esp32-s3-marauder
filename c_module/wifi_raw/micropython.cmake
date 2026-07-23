# CMake file for MicroPython user C module: _wifi_raw
#
# Usage:
#   cd micropython/ports/esp32
#   make BOARD=ESP32_S3_N16R8 USER_C_MODULES=/absolute/path/to/c_module/wifi_raw/micropython.cmake

# Create interface library for the user module
add_library(usermod_wifi_raw INTERFACE)

target_sources(usermod_wifi_raw INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/wifi_raw.c
)

target_include_directories(usermod_wifi_raw INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

# Link against ESP-IDF components required by our module
target_link_libraries(usermod_wifi_raw INTERFACE
    idf::esp_wifi
    idf::nvs_flash
    idf::esp_netif
    idf::esp_event
)

# Register with MicroPython build system
target_link_libraries(usermod INTERFACE usermod_wifi_raw)
