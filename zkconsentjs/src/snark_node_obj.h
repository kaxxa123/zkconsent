#ifndef SNARK_NODE_OBJ_H
#define SNARK_NODE_OBJ_H

//An object allowing us to keep state across javascript function calls
class ZkConsentNode : public Napi::ObjectWrap<ZkConsentNode> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    ZkConsentNode(const Napi::CallbackInfo& info);

private:
    Napi::Value StubPRFapk(const Napi::CallbackInfo& info);
    Napi::Value StubPRFConsentnf(const Napi::CallbackInfo& info);
    Napi::Value StubPRFIDnf(const Napi::CallbackInfo& info);
    Napi::Value StubPRFStudynf(const Napi::CallbackInfo& info);
    Napi::Value StubPRFHtag(const Napi::CallbackInfo& info);

    Napi::Value StubMKTree_root(const Napi::CallbackInfo& info);
    Napi::Value StubMKTree_get(const Napi::CallbackInfo& info);
    void        StubMKTree_set(const Napi::CallbackInfo& info);

    std::shared_ptr<zkc_mktree>  m_tree;
};

#endif //SNARK_NODE_OBJ_H
