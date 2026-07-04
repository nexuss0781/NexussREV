#pragma once

#include <string>
#include <vector>
#include <memory>
#include <capstone/capstone.h>
#include <LIEF/LIEF.hpp>

namespace nexusrev {

struct Function {
    std::string name;
    uint64_t address;
    size_t size;
    std::vector<uint8_t> bytes;
    std::string pseudo_code;
    bool analysis_complete = false;
    double confidence_score = 0.0;
};

struct LossMetrics {
    size_t total_functions = 0;
    size_t recovered_functions = 0;
    size_t missing_functions = 0;
    size_t recovered_bytes = 0;
    size_t total_bytes = 0;
    double code_coverage = 0.0;
    double symbol_fidelity = 0.0;
    double data_fidelity = 0.0;
    double loss_ratio = 1.0; // 0.0 is perfect
    bool reconstruction_100_percent = false;
};

class Decompiler {
public:
    Decompiler();
    ~Decompiler();

    bool load_binary(const std::string& path);
    bool analyze();
    void emit_code(const std::string& output_path);
    LossMetrics get_metrics() const { return metrics_; }

private:
    bool disassemble_function(Function& func);
    void recover_symbols();
    void analyze_control_flow(Function& func);
    void infer_types(Function& func);
    void calculate_loss_metrics();
    void perform_deep_recovery();
    void validate_reconstruction();
    std::string lift_to_pseudo_c(const Function& func);
    
    std::unique_ptr<LIEF::Binary> binary_;
    csh capstone_handle_;
    std::vector<Function> functions_;
    LossMetrics metrics_;
};

} // namespace nexusrev
