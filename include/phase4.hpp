#pragma once

#include "nexusrev.hpp"
#include <string>

namespace nexusrev {

// Performs conservative x64 Microsoft-ABI stack, signature, call-argument,
// import-prototype, and control-structure analysis. Unknowns remain explicit.
void analyze_phase4(AnalysisReport& report);

// Emits clearly labelled best-effort C-like pseudocode; never claims to be
// compilable or equivalent to the original source.
std::string emit_pseudocode(const AnalysisReport& report);

// Serialize Phase 4 records as one JSON object.
std::string phase4_analysis_to_json(const Phase4AnalysisRecord& record);

} // namespace nexusrev
