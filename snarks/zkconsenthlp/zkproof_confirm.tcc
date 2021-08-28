#ifndef __ZKPROOF_CONFIRM_TCC_
#define __ZKPROOF_CONFIRM_TCC_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
zkconfirm_gadget<FieldT,HashT,HashTreeT,TreeDepth>::zkconfirm_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
        : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    // PUBLIC DATA: allocated first so that the protoboard has access.
    cm_consent.allocate(pb, FMT(this->annotation_prefix, " cm_consent"));

    // PRIVATE DATA:
    ZERO.allocate(pb, FMT(this->annotation_prefix, " ZERO"));
    a_pk.reset(new libsnark::digest_variable<FieldT>(pb,libzeth::ZETH_A_PK_SIZE,FMT(this->annotation_prefix, " a_pk")));
    studyid.allocate(pb, ZKC_STUDYID_SIZE, FMT(this->annotation_prefix, " studyid"));
    choice.allocate(pb, FMT(this->annotation_prefix, " choice"));

}

}


#endif //__ZKPROOF_CONFIRM_TCC_
