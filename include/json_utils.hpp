#ifndef LIBUV_TLS_JSON_UTILS_H
#define LIBUV_TLS_JSON_UTILS_H

#include <sstream>
#include <jsoncpp/json/json.h>

inline Json::Value getJsonValueFromString(std::string const &in) noexcept
{
    Json::Value root;
    Json::CharReaderBuilder jsonReader;
    std::string errs;
    std::stringstream inStream(in);
    if (!Json::parseFromStream(jsonReader, inStream, &root, &errs))
    {
        return {};
    }
    return root;
}

#endif //LIBUV_TLS_JSON_UTILS_H
