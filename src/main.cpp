#include "nexusrev.hpp"
#include <iostream>
#include <chrono>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input.exe> <output.c>" << std::endl;
        return 1;
    }

    std::string input_path = argv[1];
    std::string output_path = argv[2];

    try {
        nexusrev::Decompiler decompiler;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        std::cout << "[*] Loading " << input_path << "..." << std::endl;
        if (!decompiler.load_binary(input_path)) {
            std::cerr << "[!] Failed to load binary." << std::endl;
            return 1;
        }

        if (!decompiler.analyze()) {
            std::cerr << "[!] Analysis failed." << std::endl;
            return 1;
        }

        decompiler.emit_code(output_path);
        
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff = end - start;
        
        nexusrev::LossMetrics metrics = decompiler.get_metrics();
        std::cout << "\n--- Enhanced NexusRev Loss Metrics ---" << std::endl;
        std::cout << "Total Functions:      " << metrics.total_functions << std::endl;
        std::cout << "Recovered Functions:  " << metrics.recovered_functions << std::endl;
        std::cout << "Missing Functions:    " << metrics.missing_functions << std::endl;
        std::cout << "Code Coverage:        " << (metrics.code_coverage * 100) << "%" << std::endl;
        std::cout << "Symbol Fidelity:      " << (metrics.symbol_fidelity * 100) << "%" << std::endl;
        std::cout << "Data Fidelity:        " << (metrics.data_fidelity * 100) << "%" << std::endl;
        std::cout << "Loss Ratio:           " << (metrics.loss_ratio * 100) << "%" << std::endl;
        std::cout << "Reconstruction:       " << (metrics.reconstruction_100_percent ? "100%" : "INCOMPLETE") << std::endl;
        std::cout << "Status:               " << (metrics.loss_ratio == 0 ? "ZERO LOSS ACHIEVED" : "LOSS DETECTED") << std::endl;
        std::cout << "--------------------------------------" << std::endl;
        
        std::cout << "[+] Decompilation finished in " << diff.count() << " seconds." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
