include_directories(.)

add_executable(
  MYSNARK

  main.cpp
)

target_include_directories(
  MYSNARK

  PUBLIC
  
  snarkhlp
  ${DEPENDS_DIR}/zeth/depends/libsnark
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libff
)

target_link_libraries(
  MYSNARK

  snark
  snarkhlp
)

