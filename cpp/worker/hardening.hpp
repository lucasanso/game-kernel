// Self-hardening of gk-scanworker, applied before it reads any untrusted input (docs/SECURITY.md, Isolamento).
//
// Windows: integrity level lowered to Low (the process can still read the files it analyses, but can no longer
// write to the user's files, registry or medium-integrity objects), every privilege disabled, and process
// mitigation policies: no child processes, no dynamic code, no extension-point DLLs (AppInit and similar),
// no images from remote shares or with a low label. Linux (development): no_new_privs.
// Failures are reported, never fatal; the orchestrator's Job Object limits apply in any case.
#pragma once

#include <string>
#include <vector>

namespace gk::worker {

struct Hardening {
    std::string integrity;                 // low | medium | high | system | untrusted | unknown | n/a
    bool privileges_disabled = false;
    std::vector<std::string> mitigations;  // applied
    std::vector<std::string> failures;     // attempted but refused by the system
};

Hardening harden_process();

}  // namespace gk::worker
