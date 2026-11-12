// Atomic installation of verified .gkpkg packages into <data>/signatures (contract layout:
// active/ previous/ staging/, see docs/WORK_SPLIT.md §3.3 and docs/OFFLINE_UPDATES.md).
//
//  1. lock <root>/.install.lock (one installation at a time, across processes)
//  2. single streaming pass: signature → manifest → payloads written to staging/<id>/ while hashed
//  3. refuse downgrades (package_version must be newer than the active one) unless allowed
//  4. copy the components the package does not replace from active/
//  5. validate every replaced component (YARA compile, ClamAV structure, IOC format)
//  6. write active manifest, then swap directories: active → previous, staging set → active
//     (on failure the previous set is moved back). Nothing is activated unless every step passed.
#pragma once

#include "gk/updates/package.hpp"
#include "gk/updates/validators.hpp"

#include <QHash>
#include <QJsonObject>
#include <QString>

#include <optional>
#include <vector>

namespace gk::updates {

struct InstallOptions {
    bool allowDowngrade = false;   // explicit user confirmation required in the UI
};

struct ComponentReport {
    QString component;
    QString version;
    qint64 count = 0;
    QStringList files;
    QStringList messages;          // validator warnings
};

struct InstallReport {
    bool ok = false;
    Error error;
    QStringList details;           // validator errors, recovery notes
    QString packageId;
    QString packageVersion;
    QString previousPackageVersion;
    QString keyId;
    QString publisher;
    std::vector<ComponentReport> components;   // installed (replaced) components
    QStringList keptComponents;                 // carried over from the previous active set
    QJsonObject activeManifest;

    QJsonObject toJson() const;
};

class Installer {
public:
    Installer(QString signaturesRoot, std::vector<TrustedKey> keys, QString appVersion);

    // Replace a built-in validator (e.g. the core's own YARA engine with its external variables).
    void setValidator(const QString& component, ComponentValidator validator);

    // Verify only (nothing written) — used to show the package details before the user confirms.
    VerifyResult inspect(const QString& packagePath) const;
    InstallReport install(const QString& packagePath, const InstallOptions& options = {});
    InstallReport rollback();
    // Finish or undo an installation interrupted by a crash/power loss; returns what was done.
    QStringList recoverInterrupted();

    std::optional<QJsonObject> activeManifest() const;
    QString root() const { return root_; }
    QString activeDir() const;
    QString previousDir() const;
    QString stagingDir() const;

private:
    QString root_;
    std::vector<TrustedKey> keys_;
    QString appVersion_;
    QHash<QString, ComponentValidator> validators_;
};

}  // namespace gk::updates
