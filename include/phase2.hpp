#pragma once

#include "nexusrev.hpp"
#include <string>

namespace nexusrev {

// Adds a matching PDB identity/function-symbol report and evidence-backed
// candidate boundaries to a Phase 1 PE/decode report. Input binaries and PDBs
// are parsed as data only; neither is executed.
void recover_functions(AnalysisReport& report, const std::string& requested_pdb_path);

} // namespace nexusrev
