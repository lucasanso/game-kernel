// Turns the stream of file-system changes into scan batches (M11). Pure logic with an injected clock and
// file probe, so every rule is tested without timing races:
//
//  * a file is scanned only once it stopped changing: no event for `stableMs`, two probes `stableMs` apart
//    with the same size and modification time, and readable (a file still being written is usually locked);
//    a file that never settles is released after `maxWaitMs` anyway (flagged as still being written);
//  * changes are gathered for `batchMs` after the first one, so an extraction or a copy becomes one scan;
//  * removed or renamed-away paths are dropped; directories are scanned only when they appear (moved or
//    copied in), never because their content changed — the files themselves arrive as their own events;
//  * paths under excluded folders (the program's own data, user exclusions) are ignored;
//  * when the operating system lost events, or too many paths are pending, the watched folder is rescanned
//    as a whole (the scanner's cache makes unchanged files cheap).
#pragma once

#include "gk/realtime/watcher.hpp"

#include <QHash>
#include <QString>
#include <QStringList>

#include <functional>

namespace gk::realtime {

struct BatcherOptions {
    qint64 stableMs = 2000;
    qint64 batchMs = 8000;
    qint64 maxWaitMs = 120000;
    int maxPending = 20000;
};

struct FileState {
    bool exists = false;
    bool directory = false;
    qint64 size = 0;
    qint64 mtimeMs = 0;
    bool readable = true;
};
using Probe = std::function<FileState(const QString& path)>;
FileState probeFile(const QString& path);   // the real probe (QFileInfo + an attempt to open for reading)

struct Batch {
    QStringList files;          // stable files
    QStringList folders;        // folders that appeared or must be rescanned (files inside them are not repeated)
    QStringList stillWriting;   // subset of `files` released after maxWaitMs while still changing
    [[nodiscard]] bool empty() const { return files.isEmpty() && folders.isEmpty(); }
    [[nodiscard]] QStringList targets() const { return folders + files; }
};

class ChangeBatcher {
public:
    explicit ChangeBatcher(BatcherOptions options = {}) : options_(options) {}
    void setOptions(const BatcherOptions& options) { options_ = options; }
    void setRoots(const QStringList& roots) { roots_ = roots; }
    void setExcluded(const QStringList& folders);

    void add(const Change& change, qint64 nowMs);
    void rescan(const QString& folder, qint64 nowMs);   // overflow: the whole folder
    // Probes the pending paths and, once the gathering window elapsed, returns what is ready.
    Batch take(qint64 nowMs, const Probe& probe = probeFile);
    void clear();

    [[nodiscard]] int pending() const { return static_cast<int>(entries_.size()); }
    [[nodiscard]] bool excluded(const QString& path) const;
    [[nodiscard]] int collapses() const { return collapses_; }   // times the pending set overflowed into rescans

private:
    struct Entry {
        QString path;
        qint64 firstSeen = 0;
        qint64 lastEvent = 0;
        bool structural = false;   // appeared (added / renamed in) or rescan: a directory is accepted
        bool probed = false;
        qint64 size = -1, mtime = -1;
        bool ready = false, forced = false, directory = false;
    };
    void touch(const QString& path, bool structural, qint64 nowMs);
    void dropTree(const QString& path);

    BatcherOptions options_;
    QStringList roots_, excluded_;
    QHash<QString, Entry> entries_;
    qint64 windowStart_ = -1;
    int collapses_ = 0;
};

}  // namespace gk::realtime
