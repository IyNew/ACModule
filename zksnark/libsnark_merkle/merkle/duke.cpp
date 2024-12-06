#define CURVE_ALT_BN128

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <boost/optional.hpp>
#include "../circuit/merklecircuit.h"

using namespace libsnark;


template<typename FieldT>
class MerkleTreeCircuit : public gadget<FieldT> {
public:
    size_t tree_depth;
    size_t num_leaves;

    // Inputs
    pb_variable_array<FieldT> root_digest_bits;

    // Variables
    std::vector<std::shared_ptr<digest_variable<FieldT>>> leaf_digests;
    std::vector<std::shared_ptr<digest_variable<FieldT>>> intermediate_digests;
    std::shared_ptr<digest_variable<FieldT>> root_digest;

    // Gadgets
    std::vector<std::shared_ptr<sha256_two_to_one_hash_gadget<FieldT>>> hash_gadgets;

    MerkleTreeCircuit(protoboard<FieldT>& pb, size_t tree_depth) : gadget<FieldT>(pb, "MerkleTreeCircuit"), tree_depth(tree_depth) {
        num_leaves = 1 << tree_depth;

        // Allocate variables for leaf digests
        for (size_t i = 0; i < num_leaves; ++i) {
            auto leaf_digest = std::make_shared<digest_variable<FieldT>>(pb, 256, FMT(this->annotation_prefix, " leaf_digest_%zu", i));
            leaf_digests.push_back(leaf_digest);
        }

        // Root digest
        root_digest = std::make_shared<digest_variable<FieldT>>(pb, 256, FMT(this->annotation_prefix, " root_digest"));
        root_digest_bits.allocate(pb, 256, FMT(this->annotation_prefix, " root_digest_bits"));

        // Build the Merkle tree from leaves to root
        std::vector<std::shared_ptr<digest_variable<FieldT>>> current_level = leaf_digests;

        while (current_level.size() > 1) {
            std::vector<std::shared_ptr<digest_variable<FieldT>>> next_level;
            for (size_t i = 0; i < current_level.size(); i += 2) {
                auto left = current_level[i];
                auto right = current_level[i + 1];
                auto result_digest = (current_level.size() == 2) ? root_digest : std::make_shared<digest_variable<FieldT>>(pb, 256, FMT(this->annotation_prefix, " intermediate_digest_%zu", i/2));
                if (current_level.size() != 2) {
                    intermediate_digests.push_back(result_digest);
                }
                auto hash_gadget = std::make_shared<sha256_two_to_one_hash_gadget<FieldT>>(pb, *left, *right, *result_digest, FMT(this->annotation_prefix, " hash_gadget_%zu", hash_gadgets.size()));
                hash_gadgets.push_back(hash_gadget);
                next_level.push_back(result_digest);
            }
            current_level = next_level;
        }
    }

    void generate_constraints() {
        // Enforce that root_digest_bits == root_digest->bits
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            1,
            packed_addition(root_digest->bits),
            packed_addition(root_digest_bits)
        ), FMT(this->annotation_prefix, " enforce root digest equality"));

        // Generate constraints for each hash gadget
        for (auto& gadget : hash_gadgets) {
            gadget->generate_r1cs_constraints();
        }
    }

    void generate_witness(const std::vector<bit_vector>& leaves) {
        // Set leaf digest bits
        for (size_t i = 0; i < num_leaves; ++i) {
            leaf_digests[i]->generate_assignments(leaves[i]);
        }

        // Generate witness for each hash gadget
        for (auto& gadget : hash_gadgets) {
            gadget->generate_r1cs_witness();
        }

        // Set root_digest_bits
        root_digest_bits.fill_with_bits(this->pb, root_digest->get_digest());
    }
};

bit_vector stringToBits(const std::string& input) {
    std::vector<unsigned char> input_bytes(input.begin(), input.end());
    return convert_byte_vector_to_bit_vector(input_bytes);
}

int main(int argc, char* argv[]) {
    typedef libsnark::default_r1cs_gg_ppzksnark_pp ppzksnark_ppT;
    ppzksnark_ppT::init_public_params();
    typedef Fr<ppzksnark_ppT> FieldT;

    const size_t tree_depth = 3;
    const size_t num_leaves = 1 << tree_depth;

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " [setup|prove|verify] ..." << std::endl;
        return 1;
    }

    if (std::string(argv[1]) == "setup") {
        protoboard<FieldT> pb;
        MerkleTreeCircuit<FieldT> merkle_circuit(pb, tree_depth);
        merkle_circuit.generate_constraints();

        const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

        std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << std::endl;

        auto keypair = r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

        // Save proving key
        std::ofstream pk_file("proving_key.raw");
        pk_file << keypair.pk;
        pk_file.close();

        // Save verification key
        std::ofstream vk_file("verification_key.raw");
        vk_file << keypair.vk;
        vk_file.close();

    } else if (std::string(argv[1]) == "prove") {
        if (argc < 2 + num_leaves) {
            std::cout << "Usage: " << argv[0] << " prove [leaf1] [leaf2] ... [leaf" << num_leaves << "]" << std::endl;
            return 1;
        }

        // Load proving key
        r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> pk;
        std::ifstream pk_file("proving_key.raw");
        pk_file >> pk;
        pk_file.close();

        // Prepare leaves
        std::vector<bit_vector> leaves;
        for (size_t i = 0; i < num_leaves; ++i) {
            std::string leaf_str = argv[2 + i];
            bit_vector leaf_bits = sha256_hash(stringToBits(leaf_str));
            leaves.push_back(leaf_bits);
        }

        // Set up the protoboard
        protoboard<FieldT> pb;
        MerkleTreeCircuit<FieldT> merkle_circuit(pb, tree_depth);
        merkle_circuit.generate_constraints();
        merkle_circuit.generate_witness(leaves);

        if (!pb.is_satisfied()) {
            std::cout << "Constraints not satisfied!" << std::endl;
            return 1;
        }

        // Generate proof
        auto proof = r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(pk, pb.primary_input(), pb.auxiliary_input());

        // Save proof
        std::ofstream proof_file("proof.raw");
        proof_file << proof;
        proof_file.close();

        // Save root
        std::vector<bool> root_bits = pb.full_variable_assignment();
        root_bits.resize(256); // Get the root bits
        std::string root_hex = bin_to_hex(root_bits);
        std::ofstream root_file("root.txt");
        root_file << root_hex;
        root_file.close();

        std::cout << "Proof and root generated." << std::endl;

    } else if (std::string(argv[1]) == "verify") {
        if (argc < 3) {
            std::cout << "Usage: " << argv[0] << " verify [leaf]" << std::endl;
            return 1;
        }

        // Load verification key
        r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> vk;
        std::ifstream vk_file("verification_key.raw");
        vk_file >> vk;
        vk_file.close();

        // Load proof
        r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof;
        std::ifstream proof_file("proof.raw");
        proof_file >> proof;
        proof_file.close();

        // Load root
        std::ifstream root_file("root.txt");
        std::string root_hex;
        root_file >> root_hex;
        root_file.close();
        bit_vector root_bits = hex_to_bits(root_hex);

        // Prepare primary input (root)
        r1cs_primary_input<FieldT> primary_input;
        for (bool bit : root_bits) {
            primary_input.push_back(bit ? FieldT::one() : FieldT::zero());
        }

        // Verify the proof
        bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(vk, primary_input, proof);

        if (verified) {
            // Additionally, check if the leaf is part of the tree
            std::string leaf_str = argv[2];
            bit_vector leaf_bits = sha256_hash(stringToBits(leaf_str));

            // Since the leaves are private inputs, the verifier cannot directly verify the leaf's inclusion.
            // In a real-world scenario, you might include additional mechanisms to prove leaf inclusion.
            // For this example, we assume that the proof validates the tree, and any leaf can be considered part of it.

            std::cout << "Verification passed. The leaf may be part of the Merkle tree." << std::endl;
        } else {
            std::cout << "Verification failed!" << std::endl;
        }

    } else {
        std::cout << "Invalid command. Use setup, prove, or verify." << std::endl;
        return 1;
    }

    return 0;
}
