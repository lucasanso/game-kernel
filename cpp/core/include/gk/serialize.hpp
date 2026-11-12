// JSON serialization of core results. The produced documents are the data contracts shared with
// Python (docs/INTEGRATION.md §1): field names are stable; enums are written as text.
#pragma once

#include <nlohmann/json.hpp>

#include "gk/filetype.hpp"
#include "gk/model.hpp"
#include "gk/pe.hpp"

namespace gk {

nlohmann::json to_json(const TypeInfo& info);
nlohmann::json to_json(const pe::PeInfo& info);
nlohmann::json to_json(const Location& location);      // omits empty fields, like Location.to_dict()
nlohmann::json to_json(const Evidence& evidence);
nlohmann::json to_json(const FileFeatures& features);
nlohmann::json to_json(const FileResult& result);

// Inverse of to_json (documents written by C++ or by gamekernel/core/models.py). Unknown fields are ignored;
// missing optional fields take their defaults. Throws gk::Error(InvalidFormat) on structurally invalid input.
Location location_from_json(const nlohmann::json& j);
Evidence evidence_from_json(const nlohmann::json& j);
FileFeatures features_from_json(const nlohmann::json& j);
FileResult file_result_from_json(const nlohmann::json& j);

}  // namespace gk
