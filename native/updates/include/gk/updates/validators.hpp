// Content validators run on the *staging* copy of each component before it is activated.
// A signed package proves who published it; these checks make sure the content will actually
// load (a broken rule set must never replace a working one).
#pragma once

#include <QString>
#include <QStringList>

#include <functional>

namespace gk::updates {

struct ValidationResult {
    bool ok = false;
    QStringList messages;      // errors when !ok; warnings otherwise
    qint64 count = 0;          // signatures / rules / IOC entries
};

using ComponentValidator = std::function<ValidationResult(const QString& componentDir)>;

// gamekernel-ioc JSON (format, version, entries[sha256, verdict, ...]); conflicting verdicts for the
// same hash across the component are an error.
ValidationResult validateIocDir(const QString& dir);

// ClamAV databases: CVD/CLD/CUD header (and MD5 of the CVD body), line structure of text databases.
// Authenticity of official CVDs inside a .gkpkg is covered by the package signature.
ValidationResult validateClamavDir(const QString& dir);

// YARA: real compilation with libyara (includes are refused: packages must be self-contained).
// External variables available to rules: filename, filepath, extension, filetype (strings).
// Without libyara in the build this validator fails closed.
ValidationResult validateYaraDir(const QString& dir);
bool yaraValidationAvailable();

// Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9), with or without extension.
bool isReservedWindowsName(const QString& fileName);

}  // namespace gk::updates
