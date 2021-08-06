#include <stdlib.h>

#include "libzeth/circuits/circuit_types.hpp"

#include "zkc_helpers.hpp"
#include "zkc_mktree.hpp"
#include "zkc_params.hpp"

namespace libzkconsent
{

using MKTreeT = libzeth::merkle_tree_field<FieldT, HashTreeT>;

zkc_mktree::zkc_mktree()
{
    m_mktree = std::shared_ptr<void>(new MKTreeT(TreeDepth));
}

zkc_mktree::~zkc_mktree()
{
}

std::string zkc_mktree::get_value(const size_t address) const
{
    std::shared_ptr<MKTreeT> tree = std::static_pointer_cast<MKTreeT>(m_mktree);
    FieldT  value = tree->get_value(address);
    return FieldtoString<FieldT>(value);
}

void zkc_mktree::set_value(const size_t address, const std::string& value)
{
    std::shared_ptr<MKTreeT> tree = std::static_pointer_cast<MKTreeT>(m_mktree);
    FieldT  fvalue = FieldT(value.c_str());
    tree->set_value(address, fvalue);
}

std::string zkc_mktree::get_root() const
{
    std::shared_ptr<MKTreeT> tree = std::static_pointer_cast<MKTreeT>(m_mktree);
    FieldT  value = tree->get_root();
    return FieldtoString<FieldT>(value);
}

std::vector<std::string> zkc_mktree::get_path(const size_t address) const
{
    std::shared_ptr<MKTreeT> tree   = std::static_pointer_cast<MKTreeT>(m_mktree);
    std::vector<FieldT> field_path  = tree->get_path(address);
    std::vector<std::string> path(field_path.size());

    for (size_t cnt = 0; cnt < field_path.size(); ++cnt)
        path[cnt] = FieldtoString<FieldT>(field_path[cnt]);

    return path;
}

}