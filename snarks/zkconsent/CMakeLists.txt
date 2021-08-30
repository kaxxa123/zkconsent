include_directories(.)

find_package(Boost REQUIRED COMPONENTS system filesystem program_options)
include_directories(SYSTEM ${Boost_INCLUDE_DIR})

add_executable(
  zkconsent

  main.cpp
  cmd_test.cpp
  cmd_snark.cpp
)

target_include_directories(
  zkconsent

  PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/../zkconsenthlp"
  ${DEPENDS_DIR}/zeth/depends/libsnark
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libff
)

target_link_libraries(
  zkconsent

  snark
  zkconsenthlp
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
)

