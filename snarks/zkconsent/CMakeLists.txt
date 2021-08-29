include_directories(.)

add_executable(
  zkconsent

  main.cpp
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
)

