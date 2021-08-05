// snark2node.cc using N-API

#include <napi.h>
#include <zkc_mktree.hpp>
#include "snark_node_obj.h"

Napi::Object InitAll(Napi::Env env, Napi::Object exports) {
  return ZkConsentNode::Init(env, exports);
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, InitAll)

