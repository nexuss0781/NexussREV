#include "sha256.hpp"

#include <iostream>
#include <string>

int main() {
    const std::string empty_expected =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const std::string abc_expected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    if (nexusrev::sha256("") != empty_expected) {
        std::cerr << "SHA-256 empty-string test failed\n";
        return 1;
    }
    if (nexusrev::sha256("abc") != abc_expected) {
        std::cerr << "SHA-256 abc test failed\n";
        return 1;
    }
    std::cout << "SHA-256 unit tests passed\n";
    return 0;
}
