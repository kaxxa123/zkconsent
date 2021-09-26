
#ifndef __ZKSNARKSTREAM_HPP_
#define __ZKSNARKSTREAM_HPP_

template<typename ppT, typename snarkT>
class zkSnarkStream {
public:
    static typename snarkT::keypair load_keypair(
        const boost::filesystem::path &keypair_file)
    {
        std::ifstream in_s(keypair_file.c_str(), std::ios_base::in | std::ios_base::binary);
        in_s.exceptions(std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);

        typename snarkT::keypair keypair;
        snarkT::keypair_read_bytes(keypair, in_s);
        return keypair;
    }

    static typename snarkT::proof load_proof(
        const boost::filesystem::path &proof_path)
    {
        std::ifstream in_s(proof_path.c_str(), std::ios_base::in | std::ios_base::binary);
        in_s.exceptions(std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);

        typename snarkT::proof proof;
        snarkT::proof_read_bytes(proof, in_s);
        return proof;
    }

    static void write_keypair(
        const typename snarkT::keypair &keypair,
        const boost::filesystem::path &keypair_file)
    {
        std::ofstream out_s(keypair_file.c_str(), std::ios_base::out | std::ios_base::binary);
        snarkT::keypair_write_bytes(keypair, out_s);
    }

    static void write_proving_key(
        const typename snarkT::proving_key &pk,
        const boost::filesystem::path &pk_bin_file)
    {
        std::ofstream out_s(
            pk_bin_file.c_str(), std::ios_base::out | std::ios_base::binary);
        snarkT::proving_key_write_bytes(pk, out_s);
    }

    static void write_verification_key(
        const typename snarkT::verification_key &vk,
        const boost::filesystem::path &vk_bin_file)
    {
        std::ofstream out_s(
            vk_bin_file.c_str(), std::ios_base::out | std::ios_base::binary);
        snarkT::verification_key_write_bytes(vk, out_s);
    }

    static void write_verification_json(
        const typename snarkT::verification_key &vk,
        const boost::filesystem::path &vk_json_file)
    {
        std::ofstream out_s(vk_json_file.c_str(), std::ios_base::out);
        snarkT::verification_key_write_json(vk, out_s);
    }

    static void write_extproof_to_json_file(
        const libzeth::extended_proof<ppT, snarkT> &ext_proof,
        const boost::filesystem::path &proof_path)
    {
        std::ofstream out_s(proof_path.c_str(), std::ios_base::out);
        ext_proof.write_json(out_s);
    }

    static void write_proof_to_file(
        const typename snarkT::proof &proof,
        const boost::filesystem::path &proof_path)
    {
        std::ofstream out_s(proof_path.c_str(), std::ios_base::out | std::ios_base::binary);
        snarkT::proof_write_bytes(proof, out_s);
    }

    static std::vector<FieldT> load_assignment(
        const boost::filesystem::path &assignment_path)
    {
        std::ifstream in_s(assignment_path.c_str(), std::ios_base::in | std::ios_base::binary);
        in_s.exceptions(std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);

        std::vector<FieldT> assignment;
        libzeth::r1cs_variable_assignment_read_bytes(assignment, in_s);
        return assignment;
    }

    static void write_assignment_to_file(
        const std::vector<FieldT> &assignment,
        const boost::filesystem::path &assignment_path)
    {
        std::ofstream out_s(assignment_path.c_str(), std::ios_base::out | std::ios_base::binary);
        libzeth::r1cs_variable_assignment_write_bytes(assignment, out_s);
    }
};

template<typename zkpT>
static void write_constraint_system(
    const zkpT &prover, const boost::filesystem::path &r1cs_json_file)
{
#ifdef DEBUG
    std::ofstream r1cs_stream(r1cs_json_file.c_str(), std::ios_base::out);
    libzeth::r1cs_write_json(prover.get_constraint_system(), r1cs_stream);
#endif
}

#endif // __ZKSNARKSTREAM_HPP_
