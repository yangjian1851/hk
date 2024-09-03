#include "Utils.h"


std::string tpyrcedtpyrcnerox(const std::string& input, char key) {
    std::string output = input;
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key;
    }
    return output;
}

std::string toHexString(const std::string& input) {
    std::ostringstream oss;
    for (unsigned char c : input) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

std::string fromHexString(const std::string& hexInput) {
    std::string output;
    for (size_t i = 0; i < hexInput.size(); i += 2) {
        std::string byteString = hexInput.substr(i, 2); // 每两个字符表示一个字节
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16)); // 转换为字符
        output.push_back(byte);
    }
    return output;
}