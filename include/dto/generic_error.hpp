#ifndef LIBUV_TLS_GENERIC_ERROR_HPP
#define LIBUV_TLS_GENERIC_ERROR_HPP

class generic_error
{
    static constexpr int error = -32000;
    static constexpr char *message = "Generic Error";
public:
    Json::Value toJsonValue() const
    {
        Json::Value jsonValue;
        jsonValue["error"] = error;
        jsonValue["message"] = message;
        return jsonValue;
    }
};

#endif //LIBUV_TLS_GENERIC_ERROR_HPP
