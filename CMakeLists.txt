cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# add the component directories that we want to use
set(EXTRA_COMPONENT_DIRS
  "components/"
  "components/espp/components/"
)

set(
  COMPONENTS
  # TODO: add additional esp-idf and espp components you want to use to the line below:
  main esptool_py activecpp console wifi_provisioning esp_http_server nlohmann_json cxx 
  app_trace bt esp_gdbstub esp_http_client esp_https_ota espcoredump logger
  esp_psram
  CACHE STRING
  "List of components to include"
  )


project(activecpp_esp32_demo)

set(CMAKE_CXX_STANDARD 20)
