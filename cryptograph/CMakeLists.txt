include(CheckCCompilerFlag)
include(CheckPrototypeDefinition)
include(CheckSymbolExists)

cmake_minimum_required(VERSION 3.0)

if(POLICY CMP0025)
# MUST call before project() and enable_language
  cmake_policy(SET CMP0025 NEW) # since 3.0, prefer AppleClang instead of Clang. FIXME: ios is still Clang
endif()
if(NOT CMAKE_VERSION VERSION_LESS 3.0)
  cmake_policy(SET CMP0048 NEW)
endif()
project(eddsa VERSION 0.6.0 DESCRIPTION "eddsa")# LANGUAGES C) # VERSION: cmake 3.0+

option(EDDSA_STACKCLEAN "clean all secret variables from stack" ON)
option(EDDSA_STATIC "build static version of library" ON)
option(EDDSA_SHARED "build static version of library" OFF)

if(EXISTS ${CMAKE_SOURCE_DIR}/cmake/tools/tools.cmake)
  include(${CMAKE_SOURCE_DIR}/cmake/tools/tools.cmake NO_POLICY_SCOPE)
else()
  if(POLICY CMP0022) # since 2.8.12. link_libraries()
    cmake_policy(SET CMP0022 NEW)
  endif()
  if(POLICY CMP0063) # visibility. since 3.3
    cmake_policy(SET CMP0063 NEW)
  endif()

  set(CMAKE_INCLUDE_CURRENT_DIR ON)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  set(CMAKE_C_VISIBILITY_PRESET hidden)
  set(CMAKE_CXX_VISIBILITY_PRESET hidden)
  set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
endif()

# check for memset_s and co
#
# may use new headers but old libs
#check_prototype_definition(memset_s "errno_t memset_s( void *dest, rsize_t destsz, int ch, rsize_t count )" "0" "string.h" HAVE_MEMSET_S)
check_symbol_exists(memset_s "string.h" HAVE_MEMSET_S)
#check_prototype_definition(explicit_bzero "void explicit_bzero(void *b, size_t len)" "" "string.h" HAVE_EXPLICIT_BZERO)
check_symbol_exists(explicit_bzero "string.h" HAVE_EXPLICIT_BZERO)

set(EDDSA_SRC fld.c sc.c ed.c sha512.c ed25519-sha512.c x25519.c)

if (EDDSA_STACKCLEAN)
  list(APPEND EDDSA_SRC burnstack.c)
endif ()


if (EDDSA_SHARED)
  add_library(eddsa SHARED ${EDDSA_SRC})

  if (EDDSA_STACKCLEAN)
    set_property(TARGET eddsa APPEND PROPERTY COMPILE_DEFINITIONS USE_STACKCLEAN)
  endif ()

  if (HAVE_MEMSET_S)
    set_property(TARGET eddsa APPEND PROPERTY COMPILE_DEFINITIONS HAVE_MEMSET_S)
  endif ()
  if (HAVE_EXPLICIT_BZERO)
    set_property(TARGET eddsa APPEND PROPERTY COMPILE_DEFINITIONS HAVE_EXPLICIT_BZERO)
  endif ()

  set_property(TARGET eddsa APPEND PROPERTY COMPILE_DEFINITIONS EDDSA_BUILD)

  set_property(TARGET eddsa PROPERTY VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
  set_property(TARGET eddsa PROPERTY SOVERSION ${PROJECT_VERSION_MAJOR})
  set_property(TARGET eddsa PROPERTY MACOSX_RPATH TRUE)
  install(TARGETS eddsa DESTINATION lib PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

  install(FILES eddsa.h DESTINATION include)
endif ()

if (EDDSA_STATIC)
  add_library(eddsa-static STATIC ${EDDSA_SRC})

  if (EDDSA_STACKCLEAN)
    set_property(TARGET eddsa-static APPEND PROPERTY COMPILE_DEFINITIONS USE_STACKCLEAN)
  endif ()

  if (HAVE_MEMSET_S)
    set_property(TARGET eddsa-static APPEND PROPERTY COMPILE_DEFINITIONS HAVE_MEMSET_S)
  endif ()
  if (HAVE_EXPLICIT_BZERO)
    set_property(TARGET eddsa-static APPEND PROPERTY COMPILE_DEFINITIONS HAVE_EXPLICIT_BZERO)
  endif ()

  set_property(TARGET eddsa-static APPEND PROPERTY COMPILE_DEFINITIONS EDDSA_BUILD EDDSA_STATIC)
  set_property(TARGET eddsa-static APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS EDDSA_STATIC)

  install(TARGETS eddsa-static DESTINATION lib PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif ()
