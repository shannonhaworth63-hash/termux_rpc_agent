#include "overlay_engine.hpp"

#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <string>

#include <json/json.h>

namespace {

using TestFn = bool (*)();

bool parseJsonValue(const std::string& text, Json::Value& out) {
    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    return reader->parse(text.c_str(), text.c_str() + text.size(), &out, &errs);
}

std::string jsonString(const Json::Value& value) {
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    builder["enableYAMLCompatibility"] = false;
    return Json::writeString(builder, value);
}

Json::Value makeSignedRequest(const std::string& method,
                             const Json::Value& params,
                             const Json::Value& id,
                             const std::string& secret) {
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "2.0";
    request["method"] = method;
    request["id"] = id;
    if (!params.isNull()) {
        request["params"] = params;
    }
    const std::string payload = termux::overlay::OverlayEngine::canonicalSignedPayload(method, params, id);
    request["signature"] = termux::overlay::OverlayEngine::hmacSha256Hex(secret, payload);
    return request;
}

bool test_valid_json_parsing() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value params(Json::objectValue);
    params["value"] = "hello";
    const Json::Value request = makeSignedRequest("echo", params, Json::Value(7), secret);
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["result"]["value"] == "hello";
}

bool test_malformed_json_rejected() {
    termux::overlay::OverlayEngine engine("overlay_secret");
    const std::string response = engine.handleRequest("{not valid json}");
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32700;
}

bool test_empty_input_rejected() {
    termux::overlay::OverlayEngine engine("overlay_secret");
    const std::string response = engine.handleRequest("");
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32700;
}

bool test_jsonrpc_version_validated() {
    termux::overlay::OverlayEngine engine("overlay_secret");
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "1.0";
    request["method"] = "echo";
    request["id"] = 3;
    Json::Value params(Json::objectValue);
    params["value"] = 123;
    request["params"] = params;
    request["signature"] = termux::overlay::OverlayEngine::hmacSha256Hex(
        "overlay_secret",
        termux::overlay::OverlayEngine::canonicalSignedPayload("echo", params, Json::Value(3)));
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32600;
}

bool test_missing_method_rejected() {
    termux::overlay::OverlayEngine engine("overlay_secret");
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "2.0";
    request["id"] = 4;
    request["signature"] = "abc123";
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32600;
}

bool test_invalid_method_type_rejected() {
    termux::overlay::OverlayEngine engine("overlay_secret");
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "2.0";
    request["method"] = 5;
    request["id"] = 5;
    request["signature"] = "abc123";
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32600;
}

bool test_missing_signature_rejected() {
    termux::overlay::OverlayEngine engine("overlay_secret");
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "2.0";
    request["method"] = "echo";
    request["id"] = 6;
    Json::Value params(Json::objectValue);
    params["value"] = "ok";
    request["params"] = params;
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32600;
}

bool test_missing_id_handled() {
    termux::overlay::OverlayEngine engine("overlay_secret");
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "2.0";
    request["method"] = "echo";
    Json::Value params(Json::objectValue);
    params["value"] = "noid";
    request["params"] = params;
    request["signature"] = "abc123";
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32600;
}

bool test_valid_hmac_verification() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value params(Json::objectValue);
    params["value"] = "hello";
    const Json::Value request = makeSignedRequest("echo", params, Json::Value(7), secret);
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["result"]["value"] == "hello";
}

bool test_incorrect_signature_rejected() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "2.0";
    request["method"] = "echo";
    request["id"] = 10;
    Json::Value params(Json::objectValue);
    params["value"] = "tampered";
    request["params"] = params;
    request["signature"] = "deadbeef";
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32001;
}

bool test_modified_parameters_rejected() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value params(Json::objectValue);
    params["value"] = "hello";
    Json::Value request = makeSignedRequest("echo", params, Json::Value(11), secret);
    const std::string original_signature = request["signature"].asString();
    request["params"]["value"] = "hijacked";
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32001;
}

bool test_modified_method_rejected() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value params(Json::objectValue);
    params["value"] = "hello";
    Json::Value request = makeSignedRequest("echo", params, Json::Value(12), secret);
    const std::string original_signature = request["signature"].asString();
    request["method"] = "health";
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32001;
}

bool test_modified_secret_rejected() {
    termux::overlay::OverlayEngine engine("overlay_secret");
    termux::overlay::OverlayEngine other("other_secret");
    Json::Value params(Json::objectValue);
    params["value"] = "value";
    Json::Value request = makeSignedRequest("echo", params, Json::Value(13), "overlay_secret");
    const std::string response = other.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32001;
}

bool test_malformed_hex_signature_rejected() {
    termux::overlay::OverlayEngine engine("overlay_secret");
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "2.0";
    request["method"] = "echo";
    request["id"] = 14;
    Json::Value params(Json::objectValue);
    params["value"] = "bad";
    request["params"] = params;
    request["signature"] = "zzzzzzzz";
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32602;
}

bool test_known_method_execution() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value params(Json::objectValue);
    params["value"] = "known";
    const Json::Value request = makeSignedRequest("echo", params, Json::Value(15), secret);
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["result"]["value"] == "known";
}

bool test_unknown_method_rejected() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value request = makeSignedRequest("ghost_method", Json::Value(Json::objectValue), Json::Value(16), secret);
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32601;
}

bool test_request_id_preserved() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value params(Json::objectValue);
    params["value"] = "idcheck";
    const Json::Value request = makeSignedRequest("echo", params, Json::Value(42), secret);
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["id"].asInt() == 42;
}

bool test_object_parameters() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value params(Json::objectValue);
    params["one"] = 1;
    params["two"] = "two";
    const Json::Value request = makeSignedRequest("echo", params, Json::Value(17), secret);
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["result"]["one"].asInt() == 1 && parsed["result"]["two"] == "two";
}

bool test_array_parameters() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value params(Json::arrayValue);
    params.append(2);
    params.append(4);
    params.append(6);
    const Json::Value request = makeSignedRequest("sum", params, Json::Value(18), secret);
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["result"].asInt() == 12;
}

bool test_unsupported_parameter_type_rejected() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "2.0";
    request["method"] = "echo";
    request["id"] = 19;
    request["params"] = "plain-string";
    request["signature"] = termux::overlay::OverlayEngine::hmacSha256Hex(
        secret,
        termux::overlay::OverlayEngine::canonicalSignedPayload("echo", request["params"], Json::Value(19)));
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32602;
}

bool test_worker_expiration_before_ttl() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    const auto start = std::chrono::system_clock::now();
    engine.setWorkerExpiration(start + std::chrono::minutes(30));
    Json::Value params(Json::objectValue);
    params["value"] = "ok";
    Json::Value request = makeSignedRequest("echo", params, Json::Value(20), secret);
    const std::string response = engine.handleRequest(jsonString(request), start + std::chrono::minutes(10));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed.isMember("result");
}

bool test_worker_expiration_at_ttl_boundary() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    const auto now = std::chrono::system_clock::now();
    engine.setWorkerExpiration(now);
    Json::Value params(Json::objectValue);
    params["value"] = "ok";
    Json::Value request = makeSignedRequest("echo", params, Json::Value(21), secret);
    const std::string response = engine.handleRequest(jsonString(request), now);
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32000;
}

bool test_worker_expiration_after_ttl() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    const auto now = std::chrono::system_clock::now();
    engine.setWorkerExpiration(now - std::chrono::milliseconds(1));
    Json::Value params(Json::objectValue);
    params["value"] = "ok";
    Json::Value request = makeSignedRequest("echo", params, Json::Value(22), secret);
    const std::string response = engine.handleRequest(jsonString(request), now);
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32000;
}

bool test_error_response_json_validity() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value request(Json::objectValue);
    request["jsonrpc"] = "2.0";
    request["method"] = "echo";
    request["id"] = 23;
    Json::Value params(Json::objectValue);
    params["value"] = "bad";
    request["params"] = params;
    request["signature"] = "00ff";
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["jsonrpc"] == "2.0" && parsed.isMember("error") && parsed["id"].asInt() == 23;
}

bool test_jsonrpc_error_code_preserved() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine engine(secret);
    Json::Value request = makeSignedRequest("ghost_method", Json::Value(Json::objectValue), Json::Value(24), secret);
    const std::string response = engine.handleRequest(jsonString(request));
    Json::Value parsed;
    if (!parseJsonValue(response, parsed)) return false;
    return parsed["error"]["code"].asInt() == -32601;
}

bool test_independent_engine_instances() {
    const std::string secret = "overlay_secret";
    termux::overlay::OverlayEngine a(secret), b(secret);
    const auto now = std::chrono::system_clock::now();
    a.setWorkerExpiration(now + std::chrono::minutes(5));
    b.setWorkerExpiration(now + std::chrono::minutes(20));
    Json::Value params(Json::objectValue);
    params["value"] = "shared";
    Json::Value request = makeSignedRequest("echo", params, Json::Value(25), secret);
    const std::string responseA = a.handleRequest(jsonString(request), now + std::chrono::minutes(10));
    const std::string responseB = b.handleRequest(jsonString(request), now + std::chrono::minutes(10));
    Json::Value parsedA, parsedB;
    if (!parseJsonValue(responseA, parsedA) || !parseJsonValue(responseB, parsedB)) return false;
    return parsedA["error"]["code"].asInt() == -32000 && parsedB.isMember("result");
}

std::map<std::string, TestFn> all_tests() {
    return {
        {"valid_json_parsing", test_valid_json_parsing},
        {"malformed_json_rejected", test_malformed_json_rejected},
        {"empty_input_rejected", test_empty_input_rejected},
        {"jsonrpc_version_validated", test_jsonrpc_version_validated},
        {"missing_method_rejected", test_missing_method_rejected},
        {"invalid_method_type_rejected", test_invalid_method_type_rejected},
        {"missing_signature_rejected", test_missing_signature_rejected},
        {"missing_id_handled", test_missing_id_handled},
        {"valid_hmac_verification", test_valid_hmac_verification},
        {"incorrect_signature_rejected", test_incorrect_signature_rejected},
        {"modified_parameters_rejected", test_modified_parameters_rejected},
        {"modified_method_rejected", test_modified_method_rejected},
        {"modified_secret_rejected", test_modified_secret_rejected},
        {"malformed_hex_signature_rejected", test_malformed_hex_signature_rejected},
        {"known_method_execution", test_known_method_execution},
        {"unknown_method_rejected", test_unknown_method_rejected},
        {"request_id_preserved", test_request_id_preserved},
        {"object_parameters", test_object_parameters},
        {"array_parameters", test_array_parameters},
        {"unsupported_parameter_type_rejected", test_unsupported_parameter_type_rejected},
        {"worker_expiration_before_ttl", test_worker_expiration_before_ttl},
        {"worker_expiration_at_ttl_boundary", test_worker_expiration_at_ttl_boundary},
        {"worker_expiration_after_ttl", test_worker_expiration_after_ttl},
        {"error_response_json_validity", test_error_response_json_validity},
        {"jsonrpc_error_code_preserved", test_jsonrpc_error_code_preserved},
        {"independent_engine_instances", test_independent_engine_instances},
    };
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2 || std::string(argv[1]) == "all") {
        const auto tests = all_tests();
        int failed = 0;
        for (const auto& entry : tests) {
            const bool ok = entry.second();
            if (!ok) {
                ++failed;
                std::cerr << "FAIL: " << entry.first << '\n';
            } else {
                std::cout << "PASS: " << entry.first << '\n';
            }
        }
        return failed == 0 ? 0 : 1;
    }

    const std::string name = argv[1];
    const auto tests = all_tests();
    const auto it = tests.find(name);
    if (it == tests.end()) {
        std::cerr << "Unknown test: " << name << '\n';
        return 1;
    }
    return it->second() ? 0 : 1;
}
