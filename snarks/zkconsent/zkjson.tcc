// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKJSON_TCC_
#define __ZKJSON_TCC_

template<typename snarkT>
zkterminate_json<snarkT>& zkterminate_json<snarkT>::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_sk, "a_sk");
    extract(objJSON, mkaddrId, "mkaddrId");
    extract(objJSON, rhoId_in, "rhoId_in");
    extract(objJSON, rhoId_out, "rhoId_out");
    extract(objJSON, hsig, "hsig");

    return (*this);
}

template<typename snarkT>
void zkterminate_json<snarkT>::trace()
{
    std::cout <<  std::endl;
    std::cout << " ------ zkterminate proof parameters ---------"  << std::endl;
    std::cout << " a_sk:        " << a_sk << std::endl;
    std::cout << " mkaddrId:    " << mkaddrId << std::endl;
    std::cout << " rhoId_in:    " << rhoId_in << std::endl;
    std::cout << " rhoId_out:   " << rhoId_out << std::endl;
    std::cout << " hsig:        " << hsig << std::endl;
    std::cout << " -------------------------------------------"  << std::endl;
    std::cout <<  std::endl;
}

template<typename snarkT>
libzeth::extended_proof<ppT, snarkT>    zkterminate_json<snarkT>::prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const
{
    std::vector<FieldT> out_public_data;
    return aZkp.prove_test( a_sk,                             
                            mkaddrId, rhoId_in, rhoId_out, 
                            hsig, proving_key, out_public_data);
}

//========================================================================================
template<typename snarkT>
zkmint_json<snarkT>& zkmint_json<snarkT>::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_sk, "a_sk");
    extract(objJSON, mkaddrStudy, "mkaddrStudy");
    extract(objJSON, studyid, "studyid");
    extract(objJSON, mkaddrId, "mkaddrId");
    extract(objJSON, rhoId_in, "rhoId_in");
    extract(objJSON, rhoId_out, "rhoId_out");
    extract(objJSON, rhoConsent_out, "rhoConsent_out");
    extract(objJSON, traprConsent_out, "traprConsent_out");
    extract(objJSON, choice_out, "choice_out");
    extract(objJSON, hsig, "hsig");

    return (*this);
}

template<typename snarkT>
void zkmint_json<snarkT>::trace()
{
    std::cout <<  std::endl;
    std::cout << " ------ zkmint proof parameters ---------"  << std::endl;
    std::cout << " a_sk:             " << a_sk << std::endl;
    std::cout << " mkaddrStudy:      " << mkaddrStudy << std::endl;
    std::cout << " studyid:          " << studyid << std::endl;
    std::cout << " mkaddrId:         " << mkaddrId << std::endl;
    std::cout << " rhoId_in:         " << rhoId_in << std::endl;
    std::cout << " rhoId_out:        " << rhoId_out << std::endl;
    std::cout << " rhoConsent_out:   " << rhoConsent_out << std::endl;
    std::cout << " traprConsent_out: " << traprConsent_out << std::endl;
    std::cout << " choice_out:       " << choice_out << std::endl;
    std::cout << " hsig:             " << hsig << std::endl;
    std::cout << " -------------------------------------------"  << std::endl;
    std::cout <<  std::endl;
}

template<typename snarkT>
libzeth::extended_proof<ppT, snarkT>    zkmint_json<snarkT>::prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const
{
    std::vector<FieldT> out_public_data;
    return aZkp.prove_test( a_sk, 
                            mkaddrStudy, studyid, 
                            mkaddrId, rhoId_in, rhoId_out, 
                            rhoConsent_out, traprConsent_out, 
                            choice_out, hsig, proving_key, out_public_data);
}

//========================================================================================
template<typename snarkT>
zkconsent_json<snarkT>& zkconsent_json<snarkT>::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_sk, "a_sk");
    extract(objJSON, mkaddrStudy, "mkaddrStudy");
    extract(objJSON, studyid, "studyid");
    extract(objJSON, mkaddrId, "mkaddrId");
    extract(objJSON, rhoId_in, "rhoId_in");
    extract(objJSON, rhoId_out, "rhoId_out");
    extract(objJSON, mkaddrConsent, "mkaddrConsent");
    extract(objJSON, rhoConsent_in, "rhoConsent_in");
    extract(objJSON, traprConsent_in, "traprConsent_in");
    extract(objJSON, choice_in, "choice_in");
    extract(objJSON, rhoConsent_out, "rhoConsent_out");
    extract(objJSON, traprConsent_out, "traprConsent_out");
    extract(objJSON, hsig, "hsig");

    return (*this);
}

template<typename snarkT>
void zkconsent_json<snarkT>::trace()
{
    std::cout <<  std::endl;
    std::cout << " ------ zkconsent proof parameters ---------"  << std::endl;
    std::cout << " a_sk:             " << a_sk << std::endl;
    std::cout << " mkaddrStudy:      " << mkaddrStudy << std::endl;
    std::cout << " studyid:          " << studyid << std::endl;
    std::cout << " mkaddrId:         " << mkaddrId << std::endl;
    std::cout << " rhoId_in:         " << rhoId_in << std::endl;
    std::cout << " rhoId_out:        " << rhoId_out << std::endl;
    std::cout << " mkaddrConsent:    " << mkaddrConsent << std::endl;
    std::cout << " rhoConsent_in:    " << rhoConsent_in << std::endl;
    std::cout << " traprConsent_in:  " << traprConsent_in << std::endl;
    std::cout << " choice_in:        " << choice_in << std::endl;
    std::cout << " rhoConsent_out:   " << rhoConsent_out << std::endl;
    std::cout << " traprConsent_out: " << traprConsent_out << std::endl;
    std::cout << " hsig:             " << hsig << std::endl;
    std::cout << " -------------------------------------------"  << std::endl;
    std::cout <<  std::endl;
}

template<typename snarkT>
libzeth::extended_proof<ppT, snarkT>    zkconsent_json<snarkT>::prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const
{
    std::vector<FieldT> out_public_data;
    return aZkp.prove_test( a_sk, 
                            mkaddrStudy, studyid, 
                            mkaddrId, rhoId_in, rhoId_out, 
                            mkaddrConsent, rhoConsent_in, traprConsent_in, choice_in,
                            rhoConsent_out, traprConsent_out, 
                            hsig, proving_key, out_public_data);
}

//========================================================================================
template<typename snarkT>
zkconfconsent_json<snarkT>& zkconfconsent_json<snarkT>::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_pk, "a_pk");
    extract(objJSON, studyid, "studyid");
    extract(objJSON, rho, "rho");
    extract(objJSON, trapr, "trapr");
    extract(objJSON, choice, "choice");

    return (*this);
}

template<typename snarkT>
void zkconfconsent_json<snarkT>::trace()
{
    std::cout <<  std::endl;
    std::cout << " ------ zkconfconsent proof parameters ---------"  << std::endl;
    std::cout << " a_pk:    " << a_pk << std::endl;
    std::cout << " studyid: " << studyid << std::endl;
    std::cout << " rho:     " << rho << std::endl;
    std::cout << " trapr:   " << trapr << std::endl;
    std::cout << " choice:  " << (choice? "yes" : "no") << std::endl;
    std::cout << " -------------------------------------------"  << std::endl;
    std::cout <<  std::endl;
}

template<typename snarkT>
libzeth::extended_proof<ppT, snarkT>    zkconfconsent_json<snarkT>::prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const
{
    return aZkp.prove_test(a_pk, studyid, rho, trapr, choice, proving_key);
}

//========================================================================================
template<typename snarkT>
zkconfterminate_json<snarkT>& zkconfterminate_json<snarkT>::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_pk, "a_pk");
    extract(objJSON, rho, "rho");

    return (*this);
}

template<typename snarkT>
void zkconfterminate_json<snarkT>::trace()
{
    std::cout <<  std::endl;
    std::cout << " ------ zkconfterminate proof parameters ---------"  << std::endl;
    std::cout << " a_pk:    " << a_pk << std::endl;
    std::cout << " rho:     " << rho << std::endl;
    std::cout << " -------------------------------------------"  << std::endl;
    std::cout <<  std::endl;
}

template<typename snarkT>
libzeth::extended_proof<ppT, snarkT>    zkconfterminate_json<snarkT>::prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const
{
    return aZkp.prove_test(a_pk, rho, proving_key);
}

#endif // __ZKJSON_TCC_
