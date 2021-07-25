// snark2node.cc using N-API

#include <stdlib.h>
#include <iostream>
#include <algorithm>

#include <node_api.h>
#include <prfxxx.hpp>


namespace demo {

    const char* StubPRFapk() {
        InitSnarks();

        const char* ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
        std::string apk_expected = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9";
        std::string apk = PRFapk(ask);

        std::transform(apk.begin(), apk.end(), apk.begin(), ::toupper);
        std::transform(apk_expected.begin(), apk_expected.end(), apk_expected.begin(), ::toupper);

        if (apk.compare(apk_expected) != 0)
            return nullptr;

        return apk.c_str();
    }

    napi_value Method(napi_env env, napi_callback_info args) {
        napi_value greeting;
        napi_status status;

        status = napi_create_string_utf8(env, "world", NAPI_AUTO_LENGTH, &greeting);
        if (status != napi_ok) return nullptr;
        return greeting;
    }

    napi_value init(napi_env env, napi_value exports) {
        napi_status status;
        napi_value fn;

        status = napi_create_function(env, nullptr, 0, Method, nullptr, &fn);
        if (status != napi_ok) return nullptr;

        status = napi_set_named_property(env, exports, "hello", fn);
        if (status != napi_ok) return nullptr;
        return exports;
    }

    NAPI_MODULE(NODE_GYP_MODULE_NAME, init)

}  // namespace demo