# defines var ffmpeg_dso: the ffmpeg single runtime file path
cmake_minimum_required(VERSION 3.15)
if(POLICY CMP0025)
# MUST call before project() and enable_language
  cmake_policy(SET CMP0025 NEW) # since 3.0, prefer AppleClang instead of Clang. FIXME: ios is still Clang
endif()

if(NOT DEFINED PROJECT_NAME)
# TODO: tools.cmake
  project(keygen VERSION 0.1.0 DESCRIPTION "mdk key generator and validator") # LANGUAGES C CXX CXXPCH) # VERSION: cmake 3.0+
  set(PROJECT_VERSION_TWEAK 0)
  set(CMAKE_CXX_STANDARD 23)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  #set(CMAKE_CXX_EXTENSIONS OFF)
else()
  # TODO: FindMDK
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

add_subdirectory(cryptograph)

add_library(appkey STATIC app.cpp)
target_include_directories(appkey PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    )
target_link_libraries(appkey PRIVATE eddsa-static)
if(TARGET cppcompat) # requires https://github.com/wang-bin/cppcompat
    #target_link_libraries(appkey PRIVATE cppcompat)
    link_libraries(cppcompat)
endif()
if(OHOS)
    target_link_libraries(appkey PRIVATE bundle_ndk.z)
endif()

if(NOT WINRT)
  add_executable(keygen keygen.cpp)
  target_include_directories(keygen PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/tools
    )

  target_link_libraries(keygen PRIVATE appkey)

  if(APPLE)
      target_link_libraries(keygen PRIVATE "-framework CoreFoundation")
  endif()
  if(WIN32)
      target_link_libraries(keygen PRIVATE version)
  endif()
endif()