# Ghidra headless post-script (Jython 2.7 compatible).
# Usage:
# analyzeHeadless <project-dir> <project-name> -import <sample.exe> \
#   -scriptPath tools/ghidra -postScript ExportNexussREVReference.py <out.tsv> <sample.exe>
# The executable is imported as data; this script never runs it.

import hashlib
import os
from ghidra.framework import Application


def fail(message):
    printerr("ExportNexussREVReference: " + message)
    raise Exception(message)


args = getScriptArgs()
if len(args) < 2:
    fail("expected output TSV path and original PE path")
output_path = os.path.abspath(args[0])
input_path = os.path.abspath(args[1])
if not os.path.isfile(input_path):
    fail("original PE path is not a regular file")

hasher = hashlib.sha256()
with open(input_path, "rb") as source:
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        hasher.update(chunk)
input_hash = hasher.hexdigest()
image_base = currentProgram.getImageBase().getOffset()
version = Application.getApplicationVersion()
if not version:
    fail("Ghidra did not provide its application version")

rows = []
function_manager = currentProgram.getFunctionManager()
functions = function_manager.getFunctions(True)
while functions.hasNext():
    function = functions.next()
    entry = function.getEntryPoint().getOffset() - image_base
    if 0 <= entry <= 0xffffffff:
        rows.append((entry, "F\t%d" % entry))

listing = currentProgram.getListing()
instructions = listing.getInstructions(currentProgram.getMemory().getLoadedAndInitializedAddressSet(), True)
while instructions.hasNext():
    instruction = instructions.next()
    address = instruction.getAddress().getOffset()
    from_rva = address - image_base
    if from_rva < 0 or from_rva > 0xffffffff:
        continue
    flow_type = instruction.getFlowType()
    mnemonic = instruction.getMnemonicString().lower()
    if mnemonic.startswith("ret"):
        rows.append((from_rva, "E\t%d\treturn\t-" % from_rva))
        continue
    if flow_type.isCall():
        kind = "call"
    elif flow_type.isConditional():
        kind = "conditional_branch"
    elif flow_type.isJump():
        kind = "branch"
    else:
        continue
    flows = instruction.getFlows()
    emitted = False
    if flows is not None:
        for target in flows:
            target_rva = target.getOffset() - image_base
            if 0 <= target_rva <= 0xffffffff:
                rows.append((from_rva, "E\t%d\t%s\t%d" % (from_rva, kind, target_rva)))
                emitted = True
    if not emitted:
        rows.append((from_rva, "E\t%d\t%s\t-" % (from_rva, kind)))

rows.sort(key=lambda row: (row[0], row[1]))
parent = os.path.dirname(output_path)
if parent and not os.path.isdir(parent):
    os.makedirs(parent)
with open(output_path, "w") as output:
    output.write("NEXUSREV_GHIDRA_REFERENCE\t1\t%s\t%s\n" % (input_hash, version.replace("\t", " ")))
    for _, row in rows:
        output.write(row + "\n")

println("ExportNexussREVReference: wrote %d rows to %s" % (len(rows), output_path))
