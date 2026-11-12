// Internal helpers to build Evidence records consistently.
#pragma once

#include <string>
#include <string_view>
#include <utility>

#include "gk/model.hpp"

namespace gk::analysis::detail {

inline Evidence make(std::string rule_id, std::string title, Source source, std::string_view category, Risk severity,
                     Confidence confidence, std::string description, std::string fp_note = {},
                     std::string engine = "static") {
    Evidence e;
    e.rule_id = std::move(rule_id);
    e.title = std::move(title);
    e.source = source;
    e.category = std::string(category);
    e.severity = severity;
    e.confidence = confidence;
    e.description = std::move(description);
    e.fp_note = std::move(fp_note);
    e.engine = std::move(engine);
    return e;
}

inline Location loc(std::string kind, std::string description = {}) {
    Location l;
    l.kind = std::move(kind);
    l.description = std::move(description);
    return l;
}

}  // namespace gk::analysis::detail
