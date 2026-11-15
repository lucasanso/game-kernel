// System Optimizer (M12): diagnostics that tell a player what is worth adjusting, and a safe clean-up of old
// temporary files. Nothing here changes a Windows setting: the checks only read (registry values, power plan,
// free space, memory, programs that start with Windows) and explain how to change things in Windows itself.
//
// The temporary-file clean-up is two steps. analyzeTemp() lists what would be deleted — regular files older
// than `minAgeHours` inside the temporary folders, never following links or junctions — and cleanTemp() deletes
// exactly those files, and only if each one is still unchanged (same size and time) and still inside its folder.
// Files in use stay (the deletion fails and is counted). The caller asks the user in between.
#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

#include <atomic>

namespace gk::sysopt {

struct Check {
    QString id;
    QString title;
    QString status;           // ok | attention | info | unavailable
    QString value;            // what was found, short
    QString detail;           // longer explanation (may list items)
    QString recommendation;   // what the user can do, in Windows itself (empty when nothing to do)
};
QJsonObject toJson(const Check& check);

// Read-only checks. `folders`: game/download folders whose drives are checked for free space as well.
QList<Check> diagnose(const QStringList& folders = {});

struct TempFile {
    QString path;
    qint64 size = 0;
    qint64 mtimeMs = 0;
};

struct TempPlan {
    QStringList roots;            // canonical temporary folders
    int minAgeHours = 24;
    QList<TempFile> files;        // what cleanTemp() may delete
    QStringList dirs;             // old folders removed afterwards if they end up empty (deepest first)
    qint64 bytes = 0;
    int recent = 0;               // kept: changed within minAgeHours
    int links = 0;                // kept: symbolic links / junctions (never followed)
    int unreadable = 0;           // folders that could not be listed
    bool truncated = false;       // stopped at the file limit
};
QJsonObject toJson(const TempPlan& plan);

struct CleanResult {
    int deleted = 0;
    qint64 bytesFreed = 0;
    int inUse = 0;                // could not be deleted (open by a program or access denied)
    int changed = 0;              // modified, replaced or moved since the analysis: kept
    int dirsRemoved = 0;
    QStringList problems;         // a sample of what failed, for the user
};
QJsonObject toJson(const CleanResult& result);

// The folders the program cleans: the user's temporary folder on Windows (%TEMP%) and the program's own
// <data>/temp. Elsewhere only <data>/temp (the system /tmp is shared and is left alone).
QStringList defaultTempRoots(const QString& dataDir);

TempPlan analyzeTemp(const QStringList& roots, int minAgeHours = 24, const std::atomic<bool>* cancel = nullptr,
                     int maxFiles = 200000);
CleanResult cleanTemp(const TempPlan& plan, const std::atomic<bool>* cancel = nullptr);

}  // namespace gk::sysopt
