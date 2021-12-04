// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKPROOF_WRAP_SIMPLE_HPP_
#define __ZKPROOF_WRAP_SIMPLE_HPP_

namespace libzkconsent
{

/// Wrapper around a zkp, for streaming proof/keys
template<typename   ppT,
         typename   FieldT,
         typename   HashT, 
         typename   HashTreeT,
         typename   snarkT,
         typename   ZkpT,
         size_t     TreeDepth>
class zkpbase_wrap_simp
{
public:
    zkpbase_wrap_simp();
    zkpbase_wrap_simp(const zkpbase_wrap_simp &) = delete;
    zkpbase_wrap_simp &operator=(const zkpbase_wrap_simp &) = delete;

    typename snarkT::keypair        generate_trusted_setup()    const;
    const libsnark::r1cs_constraint_system<FieldT>  
                                    &get_constraint_system()    const;
    const std::vector<FieldT>       &get_last_assignment()      const;
    
protected:
    libzeth::extended_proof<ppT, snarkT> complete_prove(
                        const typename snarkT::proving_key &proving_key) const;

    libsnark::protoboard<FieldT>        pb;
    std::shared_ptr<ZkpT>               inner_zkp;
};

//====================================================================================
template<typename   ppT, 
         typename   FieldT, 
         typename   HashT, 
         typename   HashTreeT, 
         typename   snarkT, 
         size_t     TreeDepth>
class zkconfconsent_wrap : public zkpbase_wrap_simp<ppT, FieldT, HashT, HashTreeT, snarkT,
                                                zkconfconsent_gadget<FieldT, HashT, HashTreeT, TreeDepth>,
                                                TreeDepth>
{
public:
using ZkpT =  zkconfconsent_gadget<FieldT, HashT, HashTreeT, TreeDepth>;

    libzeth::extended_proof<ppT, snarkT> prove(
        const libzeth::bits256      &apk_in,
        const libzeth::bits64       &study_in,
        const libzeth::bits256      &rho_in,
        const libzeth::bits256      &trapr_in,
        bool                        choice_in,
        const typename snarkT::proving_key &proving_key) const;

    libzeth::extended_proof<ppT, snarkT> prove_test(
        const std::string&  s_apk,
        const std::string&  s_studyid,
        const std::string&  s_rho,
        const std::string&  s_trapr,
        bool                choice,
        const typename snarkT::proving_key &proving_key) const;

    static bool test(
        const std::string&  s_apk,
        const std::string&  s_studyid,
        const std::string&  s_rho,
        const std::string&  s_trapr,
        bool                choice);
};

//================================================================================
template<typename   ppT, 
         typename   FieldT, 
         typename   HashT, 
         typename   HashTreeT, 
         typename   snarkT, 
         size_t     TreeDepth>
class zkconfterminate_wrap : public zkpbase_wrap_simp<ppT, FieldT, HashT, HashTreeT, snarkT,
                                                zkconfterminate_gadget<FieldT, HashT, HashTreeT, TreeDepth>,
                                                TreeDepth>
{
public:
using ZkpT =  zkconfterminate_gadget<FieldT, HashT, HashTreeT, TreeDepth>;

    libzeth::extended_proof<ppT, snarkT> prove(
        const libzeth::bits256      &apk_in,
        const libzeth::bits256      &rho_in,
        const typename snarkT::proving_key &proving_key) const;

    libzeth::extended_proof<ppT, snarkT> prove_test(
        const std::string&  s_apk,
        const std::string&  s_rho,
        const typename snarkT::proving_key &proving_key) const;

    static bool test(
        const std::string&  s_apk,
        const std::string&  s_rho);
};

}

#include "zkproof_wrap_simple.tcc"

#endif //__ZKPROOF_WRAP_SIMPLE_HPP_
