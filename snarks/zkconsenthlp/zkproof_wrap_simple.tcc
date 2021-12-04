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

}

#endif //__ZKPROOF_WRAP_SIMPLE_TCC_
