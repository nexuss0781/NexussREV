#pragma once

#include "nexusrev.hpp"

#include <string>

namespace nexusrev {

// Conservatively lifts the implemented x86-64 subset, builds per-function CFGs,
// and preserves unsupported instructions and unresolved edges explicitly.
void analyze_semantics(AnalysisReport& report);

// Reads the bounded NEXUSREV_GHIDRA_REFERENCE v1 TSV format emitted by the
// optional Ghidra headless export script and records differences in the report.
void compare_ghidra_reference(AnalysisReport& report, const std::string& path);

// Serialize the Phase 3 report member as one JSON object.
std::string semantic_analysis_to_json(const SemanticAnalysisRecord& record);

} // namespace nexusrev
