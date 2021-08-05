#ifndef __ZKC_MKTREE_H_
#define __ZKC_MKTREE_H_

//Thin wrapper hiding libsnark/libzeth depedencies 
class zkc_mktree
{
public:
    zkc_mktree();
    ~zkc_mktree();

    std::string get_value(const size_t address) const;
    void        set_value(const size_t address, const std::string& value);
    std::string get_root() const;
    std::vector<std::string> get_path(const size_t address) const;

    std::shared_ptr<void>   m_mktree;
};


#endif //__ZKC_MKTREE_H_