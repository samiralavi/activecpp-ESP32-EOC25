idf_component_register()

include(FetchContent)

FetchContent_Declare(json 
                    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz 
                    DOWNLOAD_EXTRACT_TIMESTAMP true)

FetchContent_MakeAvailable(json)

target_link_libraries(${COMPONENT_LIB} INTERFACE nlohmann_json::nlohmann_json)
