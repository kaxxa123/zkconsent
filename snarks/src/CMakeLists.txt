include_directories(.)

add_executable(
  MYSNARK

  main.cpp
  prfxxx.cpp
  ${DEPENDS_DIR}/zeth/libzeth/core/bits.cpp
  ${DEPENDS_DIR}/zeth/libzeth/core/utils.cpp
)

target_link_libraries(
  MYSNARK

  snark
)

target_include_directories(
  MYSNARK

  PUBLIC

  ${DEPENDS_DIR}/zeth
  ${DEPENDS_DIR}/zeth/libzeth
  ${DEPENDS_DIR}/zeth/depends/libsnark
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libff
)

