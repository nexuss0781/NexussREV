#pragma once

#include "nexusrev.hpp"
#include <string>

namespace nexusrev {

// Adds a matching PDB identity/function-symbol report and evidence-backed
// candidate boundaries to a Phase 1 PE/decode report. Input binaries and PDBs
// are parsed as data only; neither is executed.
void recover_functions(AnalysisReport& report, const std::string& requested_pdb_path);

// Classifies each input-file byte once using decoded instructions, validated
// code/data evidence, and explicit unresolved defaults; file accounting is exact.
void discover_image(AnalysisReport& report);

} // namespace nexusrev
