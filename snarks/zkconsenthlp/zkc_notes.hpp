#ifndef __ZKC_NOTES_H_
#define __ZKC_NOTES_H_

namespace libzkconsent
{

class id_note
{
public:
    libzeth::bits256 a_pk;
    libzeth::bits256 rho;

    id_note(
        const libzeth::bits256 &a_pk_in,
        const libzeth::bits256 &rho_in)
        : a_pk(a_pk_in), rho(rho_in)
    {
    }

    id_note() {}
};

class consent_note
{
public:
    libzeth::bits256 a_pk;
    libzeth::bits256 rho;
    libzeth::bits256 trap_r;
    libzeth::bits64  studyid;
    bool             choice;

    consent_note(
        const libzeth::bits256 &a_pk_in,
        const libzeth::bits256 &rho_in,
        const libzeth::bits256 &trap_r_in,
        const libzeth::bits64  &studyid_in,
        bool          choice_in)
        :   a_pk(a_pk_in), 
            rho(rho_in), 
            trap_r(trap_r_in), 
            studyid(studyid_in), 
            choice(choice_in)
    {
    }

    consent_note() {}
};

template<typename FieldT, typename NoteT, size_t TreeDepth> 
class input_note
{
public:
    std::vector<FieldT>             mkpath;
    libzeth::bits_addr<TreeDepth>   mkaddress;

    libzeth::bits256        a_sk;
    libzeth::bits256        nf;
    NoteT                   note;

    input_note(){};
    input_note(
        std::vector<FieldT>     &&mkpath_in,
        const libzeth::bits_addr<TreeDepth> &mkaddress_in,
        const libzeth::bits256  &a_sk_in,
        const libzeth::bits256  &nf_in,
        const NoteT             &note_in)
        : mkpath(std::move(mkpath_in))
        , mkaddress(mkaddress_in)
        , note(note_in)
        , a_sk(a_sk_in)
        , nf(nf_in)
    {
    }
};

}

#endif //__ZKC_NOTES_H_