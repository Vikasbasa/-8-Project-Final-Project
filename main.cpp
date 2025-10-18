#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <curl/curl.h>

//  downloaded data 
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    std::string* str = static_cast<std::string*>(userp);
    str->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

// Download data
std::string get_entire_content(const std::string &url) {
    CURL* curl = curl_easy_init();
    std::string readBuffer;
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        // Follow redirects if any
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        CURLcode res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << "\n";
            curl_easy_cleanup(curl);
            throw std::runtime_error("Failed to retrieve content.");
        }
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

// remove html

std::string strip_html(const std::string &html) {
    std::string text;
    bool inTag = false;
    for (char c : html) {
        if (c == '<') {
            inTag = true;
        } else if (c == '>') {
            inTag = false;
            text.push_back('\n'); // Optionally add a newline after each tag.
        } else if (!inTag) {
            text.push_back(c);
        }
    }
    return text;
}

// Right-rotate function for 32-bit values.
uint32_t right_rotate(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

// Apply SHA-256.
std::vector<uint8_t> sha256(const std::vector<uint8_t> &data) {
    uint32_t h[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };

    //  SHA-256 Constants
    uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    std::vector<uint8_t> msg = data;
    uint64_t original_bit_length = msg.size() * 8;

    msg.push_back(0x80);

    // Append k bits 
    while ((msg.size() * 8) % 512 != 448) {
        msg.push_back(0x00);
    }

    for (int i = 7; i >= 0; i--) {
        msg.push_back(static_cast<uint8_t>((original_bit_length >> (i * 8)) & 0xff));
    }

    for (size_t offset = 0; offset < msg.size(); offset += 64) {
        uint32_t w[64];
        // Copy chunk into first 16 words w[0..15] (big-endian)
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[offset + i*4] << 24) |
                   (msg[offset + i*4 + 1] << 16) |
                   (msg[offset + i*4 + 2] << 8) |
                   (msg[offset + i*4 + 3]);
        }
        // Extend  16 words  -- 48 words:
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff;
        }

        // Initialize working variables
        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h_val = h[7];

        // Main loop
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = (h_val + S1 + ch + k[i] + w[i]) & 0xffffffff;
            uint32_t S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = (S0 + maj) & 0xffffffff;

            h_val = g;
            g = f;
            f = e;
            e = (d + temp1) & 0xffffffff;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) & 0xffffffff;
        }

        // compressed chunk 
        h[0] = (h[0] + a) & 0xffffffff;
        h[1] = (h[1] + b) & 0xffffffff;
        h[2] = (h[2] + c) & 0xffffffff;
        h[3] = (h[3] + d) & 0xffffffff;
        h[4] = (h[4] + e) & 0xffffffff;
        h[5] = (h[5] + f) & 0xffffffff;
        h[6] = (h[6] + g) & 0xffffffff;
        h[7] = (h[7] + h_val) & 0xffffffff;
    }

    // 32 bytes hash
    std::vector<uint8_t> digest;
    for (int i = 0; i < 8; i++) {
        digest.push_back((h[i] >> 24) & 0xff);
        digest.push_back((h[i] >> 16) & 0xff);
        digest.push_back((h[i] >> 8) & 0xff);
        digest.push_back(h[i] & 0xff);
    }
    return digest;
}

std::string to_hex_string(const std::vector<uint8_t> &data) {
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return oss.str();
}

int main() {
    std::string url = "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892";

    // Retrieve the page
    std::string htmlContent;
    try {
        htmlContent = get_entire_content(url);
    } catch (const std::exception &ex) {
        std::cerr << "Error retrieving content: " << ex.what() << "\n";
        return 1;
    }


    std::string textContent = strip_html(htmlContent);

    // Print the extracted text content.
    std::cout << "Extracted Text Content:\n";
    std::cout << textContent << "\n\n";

    //  (UTF-8) to  bytes
    std::vector<uint8_t> contentBytes(textContent.begin(), textContent.end());

    std::vector<uint8_t> digest = sha256(contentBytes);
    std::string hashHex = to_hex_string(digest);

    std::cout << "SHA-256 hash of the extracted text content:\n";
    std::cout << hashHex << "\n";

    return 0;
}
