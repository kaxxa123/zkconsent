#ifndef SNARK_NODE_OBJ_H
#define SNARK_NODE_OBJ_H

//An object allowing us to keep state across javascript function calls
class ZkConsentNode : public Napi::ObjectWrap<ZkConsentNode> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  ZkConsentNode(const Napi::CallbackInfo& info);

 private:
  Napi::Value StubPRFapk(const Napi::CallbackInfo& info);
  Napi::Value StubPRFnf(const Napi::CallbackInfo& info);
};

#endif //SNARK_NODE_OBJ_H
