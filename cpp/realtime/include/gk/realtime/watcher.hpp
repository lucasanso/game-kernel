// Native, recursive directory watcher (M11).
//
// Windows (the product): ReadDirectoryChangesW with overlapped I/O on one thread for every watched folder
// (bWatchSubtree). Linux (development and CI): inotify with one watch per directory, added as directories
// appear. Other platforms: not supported (start() reports it). The watcher never opens the files it reports.
//
// Events are delivered to the thread the watcher lives in (queued signals). When the operating system loses
// events (buffer overflow), `overflow(root)` asks for a rescan of that folder instead of silently missing
// changes; when a folder can no longer be watched (removed, unmounted, access denied), `failed` says so.
#pragma once

#include <QList>
#include <QMetaType>
#include <QObject>
#include <QString>
#include <QStringList>

#include <memory>

namespace gk::realtime {

enum class ChangeKind { Added, Modified, Removed, RenamedFrom, RenamedTo };

struct Change {
    QString path;        // absolute, native separators of the platform as reported by Qt (forward slashes)
    ChangeKind kind = ChangeKind::Modified;
    bool directory = false;   // known only on Linux (inotify reports it); false = unknown/file
};

class DirectoryWatcher : public QObject {
    Q_OBJECT
public:
    explicit DirectoryWatcher(QObject* parent = nullptr);
    ~DirectoryWatcher() override;

    static bool supported();

    // A folder that could not be watched: its cleaned absolute path and the reason, in Portuguese.
    struct Refusal {
        QString folder, reason;
    };
    // Starts watching `roots` recursively, replacing any previous set. Returns the folders that could not be
    // watched (empty = all watched). Folders that do not exist are refused; a folder inside another requested
    // folder is covered by it and not watched twice.
    QList<Refusal> start(const QStringList& roots);
    // Cleaned absolute form used for every path this watcher reports (forward slashes).
    static QString cleanFolder(const QString& folder);
    void stop();
    [[nodiscard]] bool active() const;
    [[nodiscard]] QStringList roots() const;   // the folders actually being watched

signals:
    void changes(const QList<gk::realtime::Change>& batch);
    void overflow(const QString& root);
    void failed(const QString& root, const QString& message);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace gk::realtime

Q_DECLARE_METATYPE(gk::realtime::Change)
