// JSON serialization of core results. The produced documents are the data contracts shared with
// Python (docs/INTEGRATION.md §1): field names are stable; enums are written as text.
#pragma once

#include <nlohmann/json.hpp>

#include "gk/filetype.hpp"
#include "gk/pe.hpp"

namespace gk {

nlohmann::json to_json(const TypeInfo& info);
nlohmann::json to_json(const pe::PeInfo& info);

}  // namespace gk
