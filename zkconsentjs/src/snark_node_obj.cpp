#include <stdlib.h>
#include <iostream>
#include <algorithm>

#include <napi.h>
#include <zkc_interface.hpp>
#include <zkc_mktree.hpp>

#include "snark_node_obj.h"

Napi::Object ZkConsentNode::Init(Napi::Env env, Napi::Object exports) 
{
    Napi::Function func =
        DefineClass(env,
                    "ZkConsentNode",
                    {InstanceMethod("prfapk",       &ZkConsentNode::StubPRFapk),
                     InstanceMethod("prfconsentnf", &ZkConsentNode::StubPRFConsentnf),
                     InstanceMethod("prfuidnf",     &ZkConsentNode::StubPRFIDnf),
                     InstanceMethod("prfstudynf",   &ZkConsentNode::StubPRFStudynf),
                     InstanceMethod("prfhtag",      &ZkConsentNode::StubPRFHtag),

                     InstanceMethod("mktree_root",   &ZkConsentNode::StubMKTree_root),
                     InstanceMethod("mktree_get",   &ZkConsentNode::StubMKTree_get),
                     InstanceMethod("mktree_set",   &ZkConsentNode::StubMKTree_set)});

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

    libzkconsent::InitSnarks();

    m_tree = std::shared_ptr<libzkconsent::zkc_mktree>(new libzkconsent::zkc_mktree());
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
    std::string apk = libzkconsent::PRFapk(ask);
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
    std::string nf = libzkconsent::PRFConsentnf(ask, rho);
    return Napi::String::New(env, nf.c_str());
}

Napi::Value ZkConsentNode::StubPRFIDnf(const Napi::CallbackInfo& info)
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
    std::string nf = libzkconsent::PRFIDnf(ask, rho);
    return Napi::String::New(env, nf.c_str());
}

Napi::Value ZkConsentNode::StubPRFStudynf(const Napi::CallbackInfo& info)
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
    std::string sid = info[1].As<Napi::String>();
    std::string nf = libzkconsent::PRFStudynf(ask, sid);
    return Napi::String::New(env, nf.c_str());
}

Napi::Value ZkConsentNode::StubPRFHtag(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() != 3) {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString() || !info[1].IsString() || !info[2].IsNumber()) {
        Napi::TypeError::New(env, "Wrong argument types").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string  ask = info[0].As<Napi::String>();
    std::string  sid = info[1].As<Napi::String>();
    Napi::Number idx = info[2].As<Napi::Number>();

    std::string htag = libzkconsent::PRFHtag(ask, sid, idx.Uint32Value());
    return Napi::String::New(env, htag.c_str());
}

Napi::Value ZkConsentNode::StubMKTree_root(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string root = m_tree->get_root();
    return Napi::String::New(env, root.c_str());
}

Napi::Value ZkConsentNode::StubMKTree_get(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsNumber()) {
        Napi::TypeError::New(env, "Wrong argument types").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Number address = info[0].As<Napi::Number>();
    std::string  value   = m_tree->get_value(address.Uint32Value());
    return Napi::String::New(env, value.c_str());
}

void ZkConsentNode::StubMKTree_set(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return;
    }

    if (!info[0].IsNumber() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Wrong argument types").ThrowAsJavaScriptException();
        return;
    }

    Napi::Number address = info[0].As<Napi::Number>();
    std::string  value   = info[1].As<Napi::String>();
    m_tree->set_value(address.Uint32Value(), value);
}

