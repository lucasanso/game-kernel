#include "hardening.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// windows.h first
#include <sddl.h>
#else
#include <sys/prctl.h>
#endif

#include <string>

namespace gk::worker {

#ifdef _WIN32

namespace {

std::string integrity_of_current_token() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return "unknown";
    DWORD len = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &len);
    std::string result = "unknown";
    if (len > 0) {
        std::string buf(len, '\0');
        if (GetTokenInformation(token, TokenIntegrityLevel, buf.data(), len, &len)) {
            const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buf.data());
            const DWORD rid = *GetSidSubAuthority(label->Label.Sid, *GetSidSubAuthorityCount(label->Label.Sid) - 1U);
            result = rid < SECURITY_MANDATORY_LOW_RID      ? "untrusted"
                     : rid < SECURITY_MANDATORY_MEDIUM_RID ? "low"
                     : rid < SECURITY_MANDATORY_HIGH_RID   ? "medium"
                     : rid < SECURITY_MANDATORY_SYSTEM_RID ? "high"
                                                           : "system";
        }
    }
    CloseHandle(token);
    return result;
}

template <typename Policy>
void apply(Hardening& h, PROCESS_MITIGATION_POLICY which, Policy& policy, const char* name) {
    if (SetProcessMitigationPolicy(which, &policy, sizeof policy)) {
        h.mitigations.emplace_back(name);
    } else {
        h.failures.push_back(std::string(name) + " (erro " + std::to_string(GetLastError()) + ")");
    }
}

}  // namespace

Hardening harden_process() {
    Hardening h;
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY child{};
    child.NoChildProcessCreation = 1;
    apply(h, ProcessChildProcessPolicy, child, "no_child_processes");
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic{};
    dynamic.ProhibitDynamicCode = 1;
    apply(h, ProcessDynamicCodePolicy, dynamic, "no_dynamic_code");
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensions{};
    extensions.DisableExtensionPoints = 1;
    apply(h, ProcessExtensionPointDisablePolicy, extensions, "no_extension_points");
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY images{};
    images.NoRemoteImages = 1;
    images.NoLowMandatoryLabelImages = 1;
    images.PreferSystem32Images = 1;
    apply(h, ProcessImageLoadPolicy, images, "image_load_restrictions");

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        h.privileges_disabled = AdjustTokenPrivileges(token, TRUE, nullptr, 0, nullptr, nullptr) != FALSE &&
                                GetLastError() == ERROR_SUCCESS;
        if (!h.privileges_disabled) h.failures.push_back("disable_privileges (erro " + std::to_string(GetLastError()) + ")");
        PSID low = nullptr;
        if (ConvertStringSidToSidW(L"S-1-16-4096", &low)) {   // Low Mandatory Level
            TOKEN_MANDATORY_LABEL label{};
            label.Label.Attributes = SE_GROUP_INTEGRITY;
            label.Label.Sid = low;
            if (!SetTokenInformation(token, TokenIntegrityLevel, &label,
                                     static_cast<DWORD>(sizeof label + GetLengthSid(low)))) {
                h.failures.push_back("low_integrity (erro " + std::to_string(GetLastError()) + ")");
            }
            LocalFree(low);
        }
        CloseHandle(token);
    } else {
        h.failures.push_back("token (erro " + std::to_string(GetLastError()) + ")");
    }
    h.integrity = integrity_of_current_token();   // what the system now reports, not what was requested
    return h;
}

#else

Hardening harden_process() {
    Hardening h;
    h.integrity = "n/a";
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) {
        h.mitigations.emplace_back("no_new_privs");
    } else {
        h.failures.emplace_back("no_new_privs");
    }
    return h;
}

#endif

}  // namespace gk::worker
