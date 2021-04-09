# defines var ffmpeg_dso: the ffmpeg single runtime file path
cmake_minimum_required(VERSION 3.1)
if(POLICY CMP0025)
# MUST call before project() and enable_language
  cmake_policy(SET CMP0025 NEW) # since 3.0, prefer AppleClang instead of Clang. FIXME: ios is still Clang
endif()
if(POLICY CMP0063) # visibility. since 3.3
  cmake_policy(SET CMP0063 NEW)
endif()

if(NOT DEFINED PROJECT_NAME)
# TODO: tools.cmake
  project(keygen VERSION 0.1.0 DESCRIPTION "mdk key generator and validator") # LANGUAGES C CXX CXXPCH) # VERSION: cmake 3.0+
  set(PROJECT_VERSION_TWEAK 0)
  # https://crascit.com/2015/03/28/enabling-cxx11-in-cmake/ (global and specified target)
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  #set(CMAKE_CXX_EXTENSIONS OFF)
  if(CMAKE_VERSION VERSION_LESS 3.12.0 AND "x${CMAKE_CXX_SIMULATE_ID}" STREQUAL "xMSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std:c++17")
  endif()
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