#ifndef __ZKPROOF_WRAP_HPP_
#define __ZKPROOF_WRAP_HPP_

namespace libzkconsent
{

/// Wrapper around a zkp, using parameterized schemes for
/// hashing, and a snark scheme for generating keys and proofs.
template<typename   ppT,
         typename   FieldT,
         typename   HashT, 
         typename   HashTreeT,
         typename   snarkT,
         typename   ZkpT,
         size_t     TreeDepth>
class zkpbase_wrap
{
public:
    using InputHasherT  = libzeth::mimc_input_hasher<FieldT, HashTreeT>;

    zkpbase_wrap();
    zkpbase_wrap(const zkpbase_wrap &) = delete;
    zkpbase_wrap &operator=(const zkpbase_wrap &) = delete;

    typename snarkT::keypair        generate_trusted_setup() const;
    const libsnark::r1cs_constraint_system<FieldT>  
                                    &get_constraint_system() const;
    const std::vector<FieldT>       &get_last_assignment() const;

protected:
    libzeth::extended_proof<ppT, snarkT> outer_prove(
                        const typename snarkT::proving_key &proving_key,
                        std::vector<FieldT> &out_public_data) const;

    libsnark::protoboard<FieldT>        pb;
    libsnark::pb_variable<FieldT>       public_data_hash;
    libsnark::pb_variable_array<FieldT> public_data;
    std::shared_ptr<InputHasherT>       input_hasher;
    std::shared_ptr<ZkpT>               inner_zkp;
};

//====================================================================================
template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
class zkterminate_wrap : public zkpbase_wrap<ppT, FieldT, HashT, HashTreeT, snarkT,
                                                zkterminate_gadget<FieldT, HashT, HashTreeT, TreeDepth>,
                                                TreeDepth>
{
public:
using ZkpT =  zkterminate_gadget<FieldT, HashT, HashTreeT, TreeDepth>;

    // Generate inner proof and returns an extended proof
    libzeth::extended_proof<ppT, snarkT> prove(
        const libzeth::bits256      &ask_in,
        const FieldT                &mkrootId,
        const std::vector<FieldT>   &mkpathId,
        const libzeth::bits_addr<TreeDepth> &mkaddrId,
        const libzeth::bits256      &rhoId_in,
        const libzeth::bits256      &hsig_in,
        const typename snarkT::proving_key &proving_key,
        std::vector<FieldT> &out_public_data) const;

    libzeth::extended_proof<ppT, snarkT> prove_test(
        const std::string   &s_ask,
        size_t              mkaddrId, 
        const std::string   &s_rhoId,
        const std::string   &s_hsig,
        const typename snarkT::proving_key &proving_key,
        std::vector<FieldT> &out_public_data) const;

    static bool test(
        const std::string   &s_ask,
        size_t              mkaddrId, 
        const std::string   &s_rhoId,
        const std::string   &s_hsig);
};

//====================================================================================
template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
class zkmint_wrap : public zkpbase_wrap<ppT, FieldT, HashT, HashTreeT, snarkT,
                                                zkmint_gadget<FieldT, HashT, HashTreeT, TreeDepth>,
                                                TreeDepth>
{
public:
using ZkpT =  zkmint_gadget<FieldT, HashT, HashTreeT, TreeDepth>;

    // Generate inner proof and returns an extended proof
    libzeth::extended_proof<ppT, snarkT> prove(
        const libzeth::bits256      &ask_in,
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
        std::vector<FieldT> &out_public_data) const;

    libzeth::extended_proof<ppT, snarkT> prove_test(
        const std::string&  s_ask,
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
        std::vector<FieldT> &out_public_data) const;

    static bool test(
        const std::string&  s_ask,
        size_t              mkaddrStudy, 
        const std::string&  s_studyid,
        size_t              mkaddrId, 
        const std::string&  s_rhoId_in,
        const std::string&  s_rhoId_out,
        const std::string&  s_rhoConsent_out,
        const std::string&  s_traprConsent_out,
        bool                choice_out,
        const std::string   &s_hsig);
};

//====================================================================================
template<typename ppT, typename FieldT, typename HashT, typename HashTreeT, typename snarkT, size_t TreeDepth>
class zkconsent_wrap : public zkpbase_wrap<ppT, FieldT, HashT, HashTreeT, snarkT,
                                                zkconsent_gadget<FieldT, HashT, HashTreeT, TreeDepth>,
                                                TreeDepth>
{
public:
using ZkpT =  zkconsent_gadget<FieldT, HashT, HashTreeT, TreeDepth>;

    // Generate inner proof and returns an extended proof
    libzeth::extended_proof<ppT, snarkT> prove(
        const libzeth::bits256      &ask_in,
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
        std::vector<FieldT> &out_public_data) const;

    libzeth::extended_proof<ppT, snarkT> prove_test(
        const std::string&  s_ask,
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
        std::vector<FieldT> &out_public_data) const;

    static bool test(
        const std::string&  s_ask,
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
        const std::string   &s_hsig);
};

}

#include "zkproof_wrap.tcc"

#endif //__ZKPROOF_WRAP_HPP_
