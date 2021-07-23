include_directories(.)

add_executable(
  MYSNARK

  main.cpp
)

target_link_libraries(
  MYSNARK

  snark
)

target_include_directories(
  MYSNARK

  PUBLIC

  ${DEPENDS_DIR}/zeth/depends/libsnark
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libff
)

