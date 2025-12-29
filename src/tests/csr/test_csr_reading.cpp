#include <iostream>
#include <string>


#include "../../pkcs/csr.h"
int main(int argc, char** argv) {
    std::string csr_path = "test.csr";
    if (argc > 1) csr_path = argv[1];


    try {
        auto CSR = CBZ::PKCS::CertificationRequest(csr_path);
        std::cout << CSR << std::endl;

        std::cout << "Loaded CSR: " << csr_path << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Failed to load CSR '" << csr_path << "': " << e.what() << "\n";
        return 2;
    } catch (...) {
        std::cerr << "Unknown error while loading CSR '" << csr_path << "'\n";
        return 3;
    }
}
