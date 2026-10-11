#include "overlay_engine.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/hmac.h>

namespace termux::overlay {
namespace {

std::string jsonString(const Json::Value& value) {
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    builder["enableYAMLCompatibility"] = false;
    return Json::writeString(builder, value);
}

Json::Value parseJsonValue(const std::string& text) {
    Json::Value value;
    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(text.c_str(), text.c_str() + text.size(), &value, &errs)) {
        throw std::runtime_error("Malformed JSON: " + errs);
    }
    return value;
}

std::string hexEncode(const unsigned char* data, std::size_t length) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0F]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

Json::Value emptyParamsObject() {
    Json::Value params(Json::objectValue);
    return params;
}

}  // namespace

OverlayEngine::OverlayEngine(std::string secret)
    : secret_(std::move(secret)),
      worker_expiration_(std::chrono::system_clock::now() + std::chrono::hours(24)) {
    methods_["echo"] = [](const Json::Value& params) { return params; };
    methods_["ping"] = [](const Json::Value& params) {
        Json::Value response(Json::objectValue);
        response["status"] = "pong";
        if (params.isObject() && params.isMember("value")) {
            response["value"] = params["value"];
        }
        return response;
    };
    methods_["sum"] = [](const Json::Value& params) {
        if (!params.isArray()) {
            Json::Value err(Json::objectValue);
            err["status"] = "invalid_params";
            return err;
        }
        long long total = 0;
        for (const auto& item : params) {
            if (!item.isInt64() && !item.isUInt64() && !item.isDouble()) {
                Json::Value err(Json::objectValue);
                err["status"] = "invalid_params";
                return err;
            }
            total += static_cast<long long>(item.asDouble());
        }
        return Json::Value(static_cast<Json::Int64>(total));
    };
}

std::string OverlayEngine::handleRequest(const std::string& json) {
    return handleRequest(json, std::chrono::system_clock::now());
}

std::string OverlayEngine::handleRequest(const std::string& json,
                                        std::chrono::system_clock::time_point now) {
    Json::Value root;
    try {
        root = parseJsonValue(json);
    } catch (const std::exception&) {
        return jsonString(errorResponse(Json::Value(Json::nullValue), -32700, "Parse error"));
    }

    if (!root.isObject()) {
        return jsonString(errorResponse(Json::Value(Json::nullValue), -32600, "Invalid request"));
    }

    Json::Value id = Json::Value(Json::nullValue);
    if (root.isMember("id")) {
        id = root["id"];
    } else {
        // Missing ID is an error
        return jsonString(errorResponse(id, -32600, "Missing id"));
    }

    if (!root.isMember("jsonrpc") || !root["jsonrpc"].isString() || root["jsonrpc"].asString() != "2.0") {
        return jsonString(errorResponse(id, -32600, "Invalid JSON-RPC version"));
    }

    if (!root.isMember("method") || !root["method"].isString()) {
        return jsonString(errorResponse(id, -32600, "Missing or invalid method"));
    }

    if (!root.isMember("signature") || !root["signature"].isString() || root["signature"].asString().empty()) {
        return jsonString(errorResponse(id, -32600, "Missing signature"));
    }

    if (root.isMember("params") && !root["params"].isObject() && !root["params"].isArray()) {
        return jsonString(errorResponse(id, -32602, "Unsupported params type"));
    }

    if (isWorkerExpired(now)) {
        return jsonString(errorResponse(id, -32000, "Worker expired"));
    }

    const std::string method = root["method"].asString();
    const Json::Value params = root.isMember("params") ? root["params"] : emptyParamsObject();
    const std::string signature = root["signature"].asString();

    if (!isHexString(signature)) {
        return jsonString(errorResponse(id, -32602, "Malformed hexadecimal signature"));
    }

    // Reconstruct the exact canonical form using the VALUES from the request
    const std::string payload = canonicalSignedPayload(method, params, id);
    const std::string expected = hmacSha256Hex(secret_, payload);

    if (!constantTimeEquals(expected, signature)) {
        return jsonString(errorResponse(id, -32001, "Invalid HMAC signature"));
    }

    auto it = methods_.find(method);
    if (it == methods_.end()) {
        return jsonString(errorResponse(id, -32601, "Method not found"));
    }

    Json::Value result = it->second(params);
    Json::Value response(Json::objectValue);
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    response["result"] = result;
    return jsonString(response);
}

void OverlayEngine::setWorkerExpiration(std::chrono::system_clock::time_point expiration) {
    worker_expiration_ = expiration;
}

std::chrono::system_clock::time_point OverlayEngine::getWorkerExpiration() const {
    return worker_expiration_;
}

std::string OverlayEngine::canonicalSignedPayload(const std::string& method,
                                                const Json::Value& params,
                                                const Json::Value& id) {
    return method + "\n" + canonicalJsonValue(params) + "\n" + canonicalJsonValue(id);
}

std::string OverlayEngine::hmacSha256Hex(const std::string& secret, const std::string& payload) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_length = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(payload.data()), payload.size(),
         digest.data(), &digest_length);
    return hexEncode(digest.data(), digest_length);
}

bool OverlayEngine::constantTimeEquals(const std::string& lhs, const std::string& rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        diff |= static_cast<unsigned char>(lhs[i] ^ rhs[i]);
    }
    return diff == 0;
}

bool OverlayEngine::isHexString(const std::string& value) {
    if (value.empty()) {
        return false;
    }
    for (char ch : value) {
        const bool ok = (ch >= '0' && ch <= '9') ||
                        (ch >= 'a' && ch <= 'f') ||
                        (ch >= 'A' && ch <= 'F');
        if (!ok) {
            return false;
        }
    }
    return true;
}

Json::Value OverlayEngine::errorResponse(const Json::Value& id,
                                        int code,
                                        const std::string& message) const {
    Json::Value response(Json::objectValue);
    response["jsonrpc"] = "2.0";
    response["id"] = id;

    Json::Value error(Json::objectValue);
    error["code"] = code;
    error["message"] = message;
    response["error"] = error;
    return response;
}

bool OverlayEngine::isWorkerExpired(std::chrono::system_clock::time_point now) const {
    return now >= worker_expiration_;
}

std::string OverlayEngine::canonicalJsonValue(const Json::Value& value) {
    if (value.isNull()) return "null";
    if (value.isBool()) return value.asBool() ? "true" : "false";
    if (value.isInt()) return std::to_string(value.asInt());
    if (value.isInt64()) return std::to_string(value.asInt64());
    if (value.isUInt()) return std::to_string(value.asUInt());
    if (value.isUInt64()) return std::to_string(value.asUInt64());
    if (value.isDouble()) {
        std::ostringstream out;
        out << std::setprecision(17) << value.asDouble();
        return out.str();
    }
    if (value.isString()) {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        return Json::writeString(builder, value);
    }
    if (value.isArray()) {
        std::string out = "[";
        for (Json::ArrayIndex i = 0; i < value.size(); ++i) {
            if (i > 0) out += ",";
            out += canonicalJsonValue(value[i]);
        }
        out += "]";
        return out;
    }
    if (value.isObject()) {
        std::vector<std::string> keys = value.getMemberNames();
        std::sort(keys.begin(), keys.end());
        std::string out = "{";
        for (std::size_t i = 0; i < keys.size(); ++i) {
            if (i > 0) out += ",";
            out += Json::writeString(Json::StreamWriterBuilder(), keys[i]);
            out += ":";
            out += canonicalJsonValue(value[keys[i]]);
        }
        out += "}";
        return out;
    }
    return "null";
}

}  // namespace termux::overlay
