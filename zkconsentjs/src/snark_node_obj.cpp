#include <stdlib.h>
#include <iostream>
#include <algorithm>

#include <napi.h>
#include <prfxxx.hpp>

#include "snark_node_obj.h"

Napi::Object ZkConsentNode::Init(Napi::Env env, Napi::Object exports) 
{
    Napi::Function func =
        DefineClass(env,
                    "ZkConsentNode",
                    {InstanceMethod("prfapk",       &ZkConsentNode::StubPRFapk),
                     InstanceMethod("prfconsentnf", &ZkConsentNode::StubPRFConsentnf)});

    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    env.SetInstanceData(constructor);

    exports.Set("ZkConsentNode", func);
    return exports;
}

ZkConsentNode::ZkConsentNode(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<ZkConsentNode>(info) 
{
    Napi::Env env = info.Env();
    if  (info.Length() != 0) {
        Napi::TypeError::New(env, "No parameters supported.").ThrowAsJavaScriptException();
        return;
    }

    InitSnarks();
}

Napi::Value ZkConsentNode::StubPRFapk(const Napi::CallbackInfo& info) 
{
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "Wrong argument type").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string ask = info[0].As<Napi::String>();
    std::string apk = PRFapk(ask.c_str());
    return Napi::String::New(env, apk.c_str());
}

Napi::Value ZkConsentNode::StubPRFConsentnf(const Napi::CallbackInfo& info) 
{
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Wrong argument types").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string ask = info[0].As<Napi::String>();
    std::string rho = info[1].As<Napi::String>();
    std::string nf = PRFConsentnf(ask.c_str(), rho.c_str());
    return Napi::String::New(env, nf.c_str());
}



