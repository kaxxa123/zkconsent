include_directories(.)

add_library(
  zkconsenthlp
  SHARED
  zkc_helpers.cpp  
  zkc_interface.cpp
  zkc_mktree.cpp
  ${DEPENDS_DIR}/zeth/libzeth/circuits/safe_arithmetic.cpp
  ${DEPENDS_DIR}/zeth/libzeth/core/bits.cpp
  ${DEPENDS_DIR}/zeth/libzeth/core/utils.cpp
)

target_include_directories(
  zkconsenthlp

  PUBLIC

  ${DEPENDS_DIR}/zeth
  ${DEPENDS_DIR}/zeth/libzeth
  ${DEPENDS_DIR}/zeth/depends/libsnark
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/zeth/depends/libsnark/depends/libff
)

target_link_libraries(
  zkconsenthlp

  snark
)

install(TARGETS zkconsenthlp      DESTINATION lib)
install(FILES   zkc_interface.hpp DESTINATION include)
install(FILES   zkc_mktree.hpp    DESTINATION include)
