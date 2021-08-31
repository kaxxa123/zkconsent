cmake_minimum_required(VERSION 3.15)

project(consent-snark)

option(
  DEBUG
  "Enable/Disable debugging mode"
  ON
)

set(CURVE 
 "ALT_BN128" 
  CACHE  
  STRING 
  "Default curve: one of ALT_BN128, BN128, EDWARDS, MNT4, MNT6"
)

set(DEPENDS_DIR
 "${CMAKE_CURRENT_SOURCE_DIR}/depends"
  CACHE
  STRING
  "Optionally specify the dependency installation directory relative to the source directory (default: inside dependency folder)"
)

set(
  OPT_FLAGS
  ""
  CACHE
  STRING
  "Override C++ compiler optimization flags"
)

set(
  OPT_FLAGS_DEBUG
  ""
  CACHE
  STRING
  "Override C++ compiler optimization flags"
)

option(
  MULTICORE
  "Enable parallelized execution, using OpenMP"
  OFF
)

option(
  WITH_PROCPS
  "Use procps for memory profiling"
  ON
)

option(
  VERBOSE
  "Print internal messages"
  OFF
)

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  # Common compilation flags and warning configuration
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Wfatal-errors -pthread -fPIC")

  if("${MULTICORE}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
  endif()

   # Default optimizations flags (to override, use -DOPT_FLAGS=...)
  if("${OPT_FLAGS}" STREQUAL "")
    set(OPT_FLAGS "-ggdb3 -O2 -march=native -mtune=native")
  endif()

  if("${OPT_FLAGS_DEBUG}" STREQUAL "")
    set(OPT_FLAGS_DEBUG "-g -O0")
  endif()
endif()

add_definitions(-DCURVE_${CURVE})

if(${CURVE} STREQUAL "BN128")
  add_definitions(-DBN_SUPPORT_SNARK=1)
endif()

if("${VERBOSE}")
  add_definitions(-DVERBOSE=1)
endif()

if("${MULTICORE}")
  add_definitions(-DMULTICORE=1)
endif()

if("${DEBUG}")
  add_definitions(-DDEBUG=1)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OPT_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${OPT_FLAGS_DEBUG}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${OPT_FLAGS_DEBUG}")

include(FindPkgConfig)
if("${WITH_PROCPS}")
  pkg_check_modules(PROCPS REQUIRED libprocps)
else()
  add_definitions(-DNO_PROCPS)
endif()

include_directories(.)

add_subdirectory(depends)
add_subdirectory(zkconsenthlp)
add_subdirectory(zkconsent)
