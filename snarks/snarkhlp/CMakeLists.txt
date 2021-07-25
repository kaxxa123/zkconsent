include_directories(.)

add_library(
  snarkhlp
  SHARED
  prfxxx.cpp
  ${DEPENDS_DIR}/zeth/libzeth/core/bits.cpp
  ${DEPENDS_DIR}/zeth/libzeth/core/utils.cpp
)

target_include_directories(
  snarkhlp

  PUBLIC

  ${DEPENDS_DIR}/zeth
  ${DEPENDS_DIR}/zeth/libzeth
  ${DEPENDS_DIR}/zeth/depends/libsnark
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libff
)

target_link_libraries(
  snarkhlp

  snark
)

install(TARGETS snarkhlp   DESTINATION lib)
install(FILES   prfxxx.hpp DESTINATION include)
