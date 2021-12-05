// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKPROOF_WRAP_SIMPLE_TCC_
#define __ZKPROOF_WRAP_SIMPLE_TCC_

namespace libzkconsent
{
    
template<typename   ppT,
         typename   FieldT,
         typename   HashT, 
         typename   HashTreeT,
         typename   snarkT,
         typename   ZkpT,
         size_t     TreeDepth>
zkpbase_wrap_simp<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>
                            ::zkpbase_wrap_simp()
{
    inner_zkp = std::make_shared<ZkpT>(pb);
    pb.set_input_sizes(ZkpT::PUB_INPUTS);

    // Generate constraints
    inner_zkp->generate_r1cs_constraints();
}

template<typename   ppT,
         typename   FieldT,
         typename   HashT, 
         typename   HashTreeT,
         typename   snarkT,
         typename   ZkpT,
         size_t     TreeDepth>
typename snarkT::keypair zkpbase_wrap_simp<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>
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
const libsnark::r1cs_constraint_system<FieldT> &zkpbase_wrap_simp<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>
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
const std::vector<FieldT> &zkpbase_wrap_simp<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>
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
libzeth::extended_proof<ppT, snarkT> zkpbase_wrap_simp<ppT, FieldT, HashT, HashTreeT, snarkT, ZkpT, TreeDepth>
                            ::complete_prove(const typename snarkT::proving_key    &proving_key) const
{
    //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // Caller should have invoked generate_r1cs_witness() 
    // for proof
    //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    bool is_valid_witness = pb.is_satisfied();
    if (!is_valid_witness)  
        throw "FAILED: Proof witness satisfiability.";

    return libzeth::extended_proof<ppT, snarkT>(
        snarkT::generate_proof(proving_key, pb), pb.primary_input());
}

//====================================================================================
template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkconfconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::prove(const libzeth::bits256      &apk_in,
                                    const libzeth::bits64       &study_in,
                                    const libzeth::bits256      &rho_in,
                                    const libzeth::bits256      &trapr_in,
                                    bool                        choice_in,
                                    const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness(apk_in, study_in, rho_in, trapr_in, choice_in);
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkconfconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::prove_test(const std::string&  s_apk,
                                        const std::string&  s_studyid,
                                        const std::string&  s_rho,
                                        const std::string&  s_trapr,
                                        bool                choice,
                                        const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness_test(s_apk, s_studyid, s_rho, s_trapr, choice);
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
bool zkconfconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::test(const std::string&  s_apk,
                                    const std::string&  s_studyid,
                                    const std::string&  s_rho,
                                    const std::string&  s_trapr,
                                    bool                choice)
{
    zkconfconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>    aZkp;
    const typename snarkT::keypair &keys = aZkp.generate_trusted_setup();

    libzeth::extended_proof<ppT, snarkT>    res =
                aZkp.prove_test(s_apk, s_studyid, s_rho, s_trapr, choice, keys.pk);

    //prove test throws an excpetion if witness is invalid
    //so we can just return true here
    return true;
}

//================================================================================
template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkconfterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::prove(const libzeth::bits256      &apk_in,
                                    const libzeth::bits256      &rho_in,
                                    const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness(apk_in, rho_in);
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkconfterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::prove_test(const std::string&  s_apk,
                                         const std::string&  s_rho,
                                        const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness_test(s_apk, s_rho);
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
bool zkconfterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::test( const std::string&  s_apk,
                                    const std::string&  s_rho)
{
    zkconfterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>    aZkp;
    const typename snarkT::keypair &keys = aZkp.generate_trusted_setup();

    libzeth::extended_proof<ppT, snarkT>    res =
                aZkp.prove_test(s_apk, s_rho,keys.pk);

    //prove test throws an excpetion if witness is invalid
    //so we can just return true here
    return true;
}

//================================================================================
template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkterminate_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::prove(const libzeth::bits256      &ask_in,
                                    const FieldT                &mkrootId,
                                    const std::vector<FieldT>   &mkpathId,
                                    const libzeth::bits_addr<TreeDepth> &mkaddrId,
                                    const libzeth::bits256      &rhoId_in,
                                    const libzeth::bits256      &rhoId_out,
                                    const libzeth::bits256      &hsig_in,
                                    const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness(ask_in, mkrootId, mkpathId, mkaddrId, rhoId_in, rhoId_out, hsig_in);
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkterminate_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::prove_test(const std::string   &s_ask,
                                         size_t              mkaddrId, 
                                         const std::string   &s_rhoId_in,
                                         const std::string   &s_rhoId_out,
                                         const std::string   &s_hsig,
                                         const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness_test(s_ask, mkaddrId, s_rhoId_in, s_rhoId_out, s_hsig);
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
bool zkterminate_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::test(const std::string   &s_ask,
                                   size_t              mkaddrId, 
                                   const std::string   &s_rhoId_in,
                                   const std::string   &s_rhoId_out,
                                   const std::string   &s_hsig)
{
    zkterminate_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>    aZkp;
    const typename snarkT::keypair &keys = aZkp.generate_trusted_setup();

    libzeth::extended_proof<ppT, snarkT>    res =
                aZkp.prove_test(s_ask, mkaddrId, s_rhoId_in, s_rhoId_out, s_hsig, keys.pk);

    //prove test throws an excpetion if witness is invalid
    //so we can just return true here
    return true;    
}

//================================================================================
template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkmint_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
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
                                    const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness(ask_in, mkrootStudy, mkpathStudy, mkaddrStudy, study_in, mkrootId, mkpathId, mkaddrId, rhoId_in, rhoId_out, rhoConsent_out, traprConsent_out, choiceConsent_out, hsig_in);
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkmint_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::prove_test(const std::string&  s_ask,
                                         size_t              mkaddrStudy, 
                                         const std::string&  s_studyid,
                                         size_t              mkaddrId, 
                                         const std::string&  s_rhoId_in,
                                         const std::string&  s_rhoId_out,
                                         const std::string&  s_rhoConsent_out,
                                         const std::string&  s_traprConsent_out,
                                         bool                choice_out,
                                         const std::string   &s_hsig,
                                         const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness_test(s_ask, mkaddrStudy, s_studyid, mkaddrId, s_rhoId_in, s_rhoId_out, s_rhoConsent_out, s_traprConsent_out, choice_out, s_hsig );
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
bool zkmint_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::test(const std::string&  s_ask,
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
    zkmint_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>    aZkp;
    const typename snarkT::keypair &keys = aZkp.generate_trusted_setup();

    libzeth::extended_proof<ppT, snarkT>    res =
                aZkp.prove_test(s_ask, mkaddrStudy, s_studyid, mkaddrId, s_rhoId_in, s_rhoId_out, s_rhoConsent_out, s_traprConsent_out, choice_out, s_hsig, keys.pk);

    //prove test throws an excpetion if witness is invalid
    //so we can just return true here
    return true;    
}

//================================================================================
template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkconsent_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
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
                                    const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness(ask_in, mkrootStudy, mkpathStudy, mkaddrStudy, study_in, mkrootId, mkpathId, mkaddrId, 
                                            rhoId_in, rhoId_out, mkrootConsent, mkpathConsent, mkaddrConsent, rhoConsent_in, 
                                            traprConsent_in, choiceConsent_in, rhoConsent_out, traprConsent_out, hsig_in);
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
libzeth::extended_proof<ppT, snarkT> zkconsent_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::prove_test(const std::string&  s_ask,
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
                                         const typename snarkT::proving_key &proving_key) const
{
    this->inner_zkp->generate_r1cs_witness_test(s_ask, mkaddrStudy, s_studyid, mkaddrId, s_rhoId_in, s_rhoId_out, mkaddrConsent, 
                                                s_rhoConsent_in, s_traprConsent_in, choice_in, s_rhoConsent_out, s_traprConsent_out, s_hsig);
    return this->complete_prove(proving_key);
}

template<typename ppT, typename FieldT, typename HashT,  typename HashTreeT, typename snarkT, size_t TreeDepth>
bool zkconsent_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>
                            ::test(const std::string&  s_ask,
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
    zkconsent_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, TreeDepth>    aZkp;
    const typename snarkT::keypair &keys = aZkp.generate_trusted_setup();

    libzeth::extended_proof<ppT, snarkT>    res =
                aZkp.prove_test(s_ask, mkaddrStudy, s_studyid, mkaddrId,  s_rhoId_in, s_rhoId_out, mkaddrConsent,  s_rhoConsent_in, 
                                s_traprConsent_in, choice_in, s_rhoConsent_out, s_traprConsent_out, s_hsig, keys.pk);

    //prove test throws an excpetion if witness is invalid
    //so we can just return true here
    return true;    
}


}

#endif //__ZKPROOF_WRAP_SIMPLE_TCC_
