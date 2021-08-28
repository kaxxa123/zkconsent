#ifndef __ZKPROOF_WRAP_HASH_TCC_
#define __ZKPROOF_WRAP_HASH_TCC_

namespace libzkconsent
{

template<typename   ppT,
         typename   FieldT,
         typename   HashT, 
         typename   HashTreeT,
         typename   snarkT,
         typename   ZkpT,
         size_t     TreeDepth>
zkpbase_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>::zkpbase_wrap()
{
    // The ZKP wrapper will have a single input a hash
    // of all the inputs of the wrapped ZKP
    public_data_hash.allocate(pb, "public_data_hash");
    pb.set_input_sizes(1);

    inner_zkp = std::make_shared<ZkpT>(pb);
    const size_t innerPubInputs = ZkpT::PUB_INPUTS;

    // Populate public_data to represent the inner zkp public data. 
    // Skip the first 2 variables (the constant 1, and the digest of the
    // public_data), and use the innerPubInputs variables that follow.
    public_data.reserve(innerPubInputs);
    for (size_t icnt = 0; icnt < innerPubInputs; ++icnt)
        public_data.emplace_back(icnt + 2);

    assert(public_data.size() == innerPubInputs);

    // Initialize the input hasher gadget
    input_hasher = std::make_shared<InputHasherT>(
        pb, public_data, public_data_hash, "input_hasher");

    // Generate constraints
    inner_zkp->generate_r1cs_constraints();
    input_hasher->generate_r1cs_constraints();
}

template<typename   ppT,
         typename   FieldT,
         typename   HashT, 
         typename   HashTreeT,
         typename   snarkT,
         typename   ZkpT,
         size_t     TreeDepth>
typename snarkT::keypair zkpbase_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>
                            ::generate_trusted_setup() const
{
    // Generate a verification and proving key (trusted setup) 
    return snarkT::generate_setup(pb);
}

template<typename   ppT,
         typename   FieldT,
         typename   HashT, 
         typename   HashTreeT,
         typename   snarkT,
         typename   ZkpT,
         size_t     TreeDepth>
const libsnark::r1cs_constraint_system<FieldT> &zkpbase_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>
                            ::get_constraint_system() const
{
    return pb.get_constraint_system();
}

template<typename   ppT,
         typename   FieldT,
         typename   HashT, 
         typename   HashTreeT,
         typename   snarkT,
         typename   ZkpT,
         size_t     TreeDepth>
const std::vector<FieldT> &zkpbase_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>
                            ::get_last_assignment() const
{
    return pb.full_variable_assignment();
}

template<typename   ppT,
         typename   FieldT,
         typename   HashT, 
         typename   HashTreeT,
         typename   snarkT,
         typename   ZkpT,
         size_t     TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkpbase_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>
                            ::outer_prove(const typename snarkT::proving_key    &proving_key,
                                          std::vector<FieldT>                   &out_public_data) const
{
    //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // Caller should have invoked generate_r1cs_witness() 
    // for inner proof
    //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    input_hasher->generate_r1cs_witness();

    bool is_valid_witness = pb.is_satisfied();
    if (!is_valid_witness)  
        throw "FAILED: Proof witness satisfiability.";

    // Fill out the public data vector
    const size_t innerPubInputs = ZkpT::PUB_INPUTS;
    out_public_data.resize(0);
    out_public_data.reserve(innerPubInputs);
    for (size_t icnt = 0; icnt < innerPubInputs; ++icnt)
        out_public_data.push_back(pb.val(public_data[icnt]));

    return libzeth::extended_proof<ppT, snarkT>(
        snarkT::generate_proof(proving_key, pb), pb.primary_input());
}

//====================================================================================
template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                        ::prove(const libzeth::bits256      &ask_in,
                                const FieldT                &mkrootId,
                                const std::vector<FieldT>   &mkpathId,
                                const libzeth::bits_addr<TreeDepth> &mkaddrId,
                                const libzeth::bits256      &rhoId_in,
                                const libzeth::bits256      &hsig_in,
                                const typename snarkT::proving_key &proving_key,
                                std::vector<FieldT> &out_public_data) const
{
    this->inner_zkp->generate_r1cs_witness(ask_in, mkrootId, mkpathId, mkaddrId, rhoId_in, hsig_in);
    return this->outer_prove(proving_key, out_public_data);
}

template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                        ::prove_test(const std::string  &s_ask,
                                    size_t              mkaddrId, 
                                    const std::string   &s_rhoId,
                                    const std::string   &s_hsig,
                                    const typename snarkT::proving_key &proving_key,
                                    std::vector<FieldT> &out_public_data) const
{
    this->inner_zkp->generate_r1cs_witness_test(s_ask, mkaddrId, s_rhoId, s_hsig);
    return this->outer_prove(proving_key, out_public_data);
}

template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
bool zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>::test(
                                    const std::string   &s_ask,
                                    size_t              mkaddrId, 
                                    const std::string   &s_rhoId,
                                    const std::string   &s_hsig)
{
    zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>    aZkp;

    const typename snarkT::keypair &keys = aZkp.generate_trusted_setup();
    std::vector<FieldT> out_public_data;

    libzeth::extended_proof<ppT, snarkT>    res =
                aZkp.prove_test(s_ask,
                                mkaddrId, 
                                s_rhoId,
                                s_hsig,
                                keys.pk,
                                out_public_data);

    //prove test throws an excpetion if witness is invalid
    //so we can just return true here
    return true;
}

//====================================================================================
template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkmint_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                        ::prove(const libzeth::bits256      &ask_in,
                                const FieldT                &mkrootStudy,
                                const std::vector<FieldT>   &mkpathStudy,
                                const libzeth::bits_addr<TreeDepth> &mkaddrStudy,
                                const libzeth::bits64       &study_in,
                                const FieldT                &mkrootId,
                                const std::vector<FieldT>   &mkpathId,
                                const libzeth::bits_addr<TreeDepth> &mkaddrId,
                                const libzeth::bits256      &rhoId_in,
                                const libzeth::bits256      &rhoId_out,
                                const libzeth::bits256      &rhoConsent_out,
                                const libzeth::bits256      &traprConsent_out,
                                bool                        choiceConsent_out,
                                const libzeth::bits256      &hsig_in,
                                const typename snarkT::proving_key &proving_key,
                                std::vector<FieldT> &out_public_data) const
{
    this->inner_zkp->generate_r1cs_witness(
                            ask_in,
                            mkrootStudy,mkpathStudy,mkaddrStudy,study_in,
                            mkrootId,mkpathId,mkaddrId,rhoId_in,rhoId_out,
                            rhoConsent_out,traprConsent_out,choiceConsent_out,
                            hsig_in);

    return this->outer_prove(proving_key, out_public_data);
}

template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkmint_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                        ::prove_test(const std::string  &s_ask,
                                    size_t              mkaddrStudy, 
                                    const std::string&  s_studyid,
                                    size_t              mkaddrId, 
                                    const std::string&  s_rhoId_in,
                                    const std::string&  s_rhoId_out,
                                    const std::string&  s_rhoConsent_out,
                                    const std::string&  s_traprConsent_out,
                                    bool                choice_out,
                                    const std::string   &s_hsig,
                                    const typename snarkT::proving_key &proving_key,
                                    std::vector<FieldT> &out_public_data) const
{
    this->inner_zkp->generate_r1cs_witness_test(s_ask, 
                                                mkaddrStudy, s_studyid,
                                                mkaddrId, s_rhoId_in, s_rhoId_out,
                                                s_rhoConsent_out, s_traprConsent_out,
                                                choice_out, s_hsig);
    return this->outer_prove(proving_key, out_public_data);
}

template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
bool zkmint_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>::test(
                                    const std::string   &s_ask,
                                    size_t              mkaddrStudy, 
                                    const std::string&  s_studyid,
                                    size_t              mkaddrId, 
                                    const std::string&  s_rhoId_in,
                                    const std::string&  s_rhoId_out,
                                    const std::string&  s_rhoConsent_out,
                                    const std::string&  s_traprConsent_out,
                                    bool                choice_out,
                                    const std::string   &s_hsig)
{
    zkmint_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>    aZkp;

    const typename snarkT::keypair &keys = aZkp.generate_trusted_setup();
    std::vector<FieldT> out_public_data;

    libzeth::extended_proof<ppT, snarkT>    res =
                aZkp.prove_test(s_ask,
                                mkaddrStudy, s_studyid,
                                mkaddrId, s_rhoId_in, s_rhoId_out,
                                s_rhoConsent_out, s_traprConsent_out,
                                choice_out, s_hsig,
                                keys.pk,
                                out_public_data);

    //prove test throws an excpetion if witness is invalid
    //so we can just return true here
    return true;
}

//====================================================================================
template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                        ::prove(const libzeth::bits256      &ask_in,
                                const FieldT                &mkrootStudy,
                                const std::vector<FieldT>   &mkpathStudy,
                                const libzeth::bits_addr<TreeDepth> &mkaddrStudy,
                                const libzeth::bits64       &study_in,
                                const FieldT                &mkrootId,
                                const std::vector<FieldT>   &mkpathId,
                                const libzeth::bits_addr<TreeDepth> &mkaddrId,
                                const libzeth::bits256      &rhoId_in,
                                const libzeth::bits256      &rhoId_out,
                                const FieldT                &mkrootConsent,
                                const std::vector<FieldT>   &mkpathConsent,
                                const libzeth::bits_addr<TreeDepth> &mkaddrConsent,
                                const libzeth::bits256      &rhoConsent_in,
                                const libzeth::bits256      &traprConsent_in,
                                bool                        choiceConsent_in,
                                const libzeth::bits256      &rhoConsent_out,
                                const libzeth::bits256      &traprConsent_out,
                                const libzeth::bits256      &hsig_in,
                                const typename snarkT::proving_key &proving_key,
                                std::vector<FieldT> &out_public_data) const
{
    this->inner_zkp->generate_r1cs_witness(
                            ask_in,
                            mkrootStudy, mkpathStudy, mkaddrStudy, study_in,
                            mkrootId, mkpathId, mkaddrId, rhoId_in, rhoId_out,
                            mkrootConsent, mkpathConsent, mkaddrConsent, rhoConsent_in, traprConsent_in, choiceConsent_in,
                            rhoConsent_out, traprConsent_out,
                            hsig_in);

    return this->outer_prove(proving_key, out_public_data);
}

template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                        ::prove_test(const std::string  &s_ask,
                                    size_t              mkaddrStudy, 
                                    const std::string&  s_studyid,
                                    size_t              mkaddrId, 
                                    const std::string&  s_rhoId_in,
                                    const std::string&  s_rhoId_out,
                                    size_t              mkaddrConsent, 
                                    const std::string&  s_rhoConsent_in,
                                    const std::string&  s_traprConsent_in,
                                    bool                choice_in,
                                    const std::string&  s_rhoConsent_out,
                                    const std::string&  s_traprConsent_out,
                                    const std::string   &s_hsig,
                                    const typename snarkT::proving_key &proving_key,
                                    std::vector<FieldT> &out_public_data) const
{
    this->inner_zkp->generate_r1cs_witness_test(
                            s_ask, 
                            mkaddrStudy, s_studyid,
                            mkaddrId, s_rhoId_in, s_rhoId_out,
                            mkaddrConsent, s_rhoConsent_in, s_traprConsent_in, choice_in,
                            s_rhoConsent_out, s_traprConsent_out,
                            s_hsig);

    return this->outer_prove(proving_key, out_public_data);
}

template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
bool zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>::test(
                                    const std::string   &s_ask,
                                    size_t              mkaddrStudy, 
                                    const std::string&  s_studyid,
                                    size_t              mkaddrId, 
                                    const std::string&  s_rhoId_in,
                                    const std::string&  s_rhoId_out,
                                    size_t              mkaddrConsent, 
                                    const std::string&  s_rhoConsent_in,
                                    const std::string&  s_traprConsent_in,
                                    bool                choice_in,
                                    const std::string&  s_rhoConsent_out,
                                    const std::string&  s_traprConsent_out,
                                    const std::string   &s_hsig)
{
    zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>    aZkp;

    const typename snarkT::keypair &keys = aZkp.generate_trusted_setup();
    std::vector<FieldT> out_public_data;

    libzeth::extended_proof<ppT, snarkT>    res =
                aZkp.prove_test(s_ask,
                                mkaddrStudy, s_studyid,
                                mkaddrId, s_rhoId_in, s_rhoId_out,
                                mkaddrConsent, s_rhoConsent_in, s_traprConsent_in, choice_in,
                                s_rhoConsent_out, s_traprConsent_out,
                                s_hsig,
                                keys.pk,
                                out_public_data);

    //prove test throws an excpetion if witness is invalid
    //so we can just return true here
    return true;
}

}

#endif //__ZKPROOF_WRAP_HASH_TCC_
