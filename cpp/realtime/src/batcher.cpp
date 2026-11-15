#include "gk/realtime/batcher.hpp"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <algorithm>
#include <utility>

namespace gk::realtime {

namespace {

Qt::CaseSensitivity pathCase() {
#ifdef _WIN32
    return Qt::CaseInsensitive;   // NTFS default
#else
    return Qt::CaseSensitive;
#endif
}

QString keyOf(const QString& path) { return pathCase() == Qt::CaseInsensitive ? path.toLower() : path; }

bool under(const QString& path, const QString& folder) {
    if (path.compare(folder, pathCase()) == 0) return true;
    const QString prefix = folder.endsWith(QLatin1Char('/')) ? folder : folder + QLatin1Char('/');
    return path.startsWith(prefix, pathCase());
}

QString clean(const QString& path) { return QDir::cleanPath(QDir::fromNativeSeparators(path)); }

}  // namespace

FileState probeFile(const QString& path) {
    FileState s;
    const QFileInfo info(path);
    // Links are not followed (as in the scanner's enumeration); their targets inside a watched folder produce
    // their own events. Windows shortcuts (.lnk) are regular files and are scanned.
    if (info.isSymbolicLink() || info.isJunction() || !info.exists()) return s;
    s.exists = true;
    s.directory = info.isDir();
    s.size = info.size();
    s.mtimeMs = info.lastModified().toMSecsSinceEpoch();
    if (!s.directory) {
        QFile f(path);
        s.readable = f.open(QIODevice::ReadOnly);   // a file still being written is usually locked
    }
    return s;
}

void ChangeBatcher::setExcluded(const QStringList& folders) {
    excluded_.clear();
    for (const QString& f : folders) {
        if (f.trimmed().isEmpty()) continue;
        // Paths reported by the watcher are absolute; relative settings are resolved like the scanner does.
        excluded_.append(clean(QDir::isAbsolutePath(f) ? f : QFileInfo(f).absoluteFilePath()));
    }
}

bool ChangeBatcher::excluded(const QString& path) const {
    const QString p = clean(path);
    return std::any_of(excluded_.begin(), excluded_.end(), [&](const QString& e) { return under(p, e); });
}

void ChangeBatcher::add(const Change& change, qint64 nowMs) {
    const QString path = clean(change.path);
    if (excluded(path)) return;
    switch (change.kind) {
        case ChangeKind::Removed:
        case ChangeKind::RenamedFrom:
            dropTree(path);
            return;
        case ChangeKind::Added:
        case ChangeKind::RenamedTo:
            touch(path, true, nowMs);
            return;
        case ChangeKind::Modified:
            if (!change.directory) touch(path, false, nowMs);
            return;
    }
}

void ChangeBatcher::rescan(const QString& folder, qint64 nowMs) {
    const QString path = clean(folder);
    if (!excluded(path)) touch(path, true, nowMs);
}

void ChangeBatcher::touch(const QString& path, bool structural, qint64 nowMs) {
    const QString key = keyOf(path);
    auto it = entries_.find(key);
    if (it == entries_.end()) {
        if (entries_.size() >= options_.maxPending && !roots_.isEmpty()) {
            // Too much at once (a huge extraction): rescan the watched folders instead of tracking each path.
            ++collapses_;
            entries_.clear();
            for (const QString& root : roots_) {
                Entry e;
                e.path = clean(root);
                e.firstSeen = e.lastEvent = nowMs;
                e.structural = true;
                entries_.insert(keyOf(e.path), e);
            }
            if (windowStart_ < 0) windowStart_ = nowMs;
            if (std::any_of(roots_.begin(), roots_.end(), [&](const QString& r) { return under(path, clean(r)); })) return;
        }
        Entry e;
        e.path = path;
        e.firstSeen = e.lastEvent = nowMs;
        e.structural = structural;
        entries_.insert(key, e);
    } else {
        it->lastEvent = nowMs;
        it->structural = it->structural || structural;
        it->ready = it->forced = false;
    }
    if (windowStart_ < 0) windowStart_ = nowMs;
}

void ChangeBatcher::dropTree(const QString& path) {
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (under(it->path, path)) it = entries_.erase(it);
        else ++it;
    }
    if (entries_.isEmpty()) windowStart_ = -1;
}

void ChangeBatcher::clear() {
    entries_.clear();
    windowStart_ = -1;
}

Batch ChangeBatcher::take(qint64 nowMs, const Probe& probe) {
    Batch batch;
    for (auto it = entries_.begin(); it != entries_.end();) {
        Entry& e = *it;
        if (e.ready || nowMs - e.lastEvent < options_.stableMs) {
            ++it;
            continue;
        }
        const FileState st = probe(e.path);
        if (!st.exists || (st.directory && !e.structural)) {
            it = entries_.erase(it);   // gone, or a folder whose content changed (its files have their own events)
            continue;
        }
        if (st.directory) {
            e.ready = e.directory = true;
            ++it;
            continue;
        }
        const bool overdue = nowMs - e.firstSeen >= options_.maxWaitMs;
        if (!e.probed || st.size != e.size || st.mtimeMs != e.mtime) {
            // First look, or still changing: the stability period starts again from this probe.
            e.probed = true;
            e.size = st.size;
            e.mtime = st.mtimeMs;
            e.lastEvent = nowMs;
            if (overdue) e.ready = e.forced = true;
            ++it;
            continue;
        }
        if (!st.readable && !overdue) {
            ++it;
            continue;
        }
        e.ready = true;
        e.forced = !st.readable;
        ++it;
    }
    if (entries_.isEmpty()) {
        windowStart_ = -1;
        return batch;
    }
    if (windowStart_ < 0 || nowMs - windowStart_ < options_.batchMs) return batch;

    QStringList folders;
    for (const Entry& e : std::as_const(entries_))
        if (e.ready && e.directory) folders.append(e.path);
    std::sort(folders.begin(), folders.end(), [](const QString& a, const QString& b) { return a.size() < b.size(); });
    for (const QString& f : folders)
        if (std::none_of(batch.folders.begin(), batch.folders.end(), [&](const QString& o) { return under(f, o); }))
            batch.folders.append(f);
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (!it->ready) {
            ++it;
            continue;
        }
        if (!it->directory &&
            std::none_of(batch.folders.begin(), batch.folders.end(), [&](const QString& o) { return under(it->path, o); })) {
            batch.files.append(it->path);
            if (it->forced) batch.stillWriting.append(it->path);
        }
        it = entries_.erase(it);
    }
    batch.folders.sort();
    batch.files.sort();
    batch.stillWriting.sort();
    // What is still pending gets a new gathering window; with nothing released, the elapsed window stays
    // open so the next file that settles goes out at once.
    if (entries_.isEmpty()) windowStart_ = -1;
    else if (!batch.empty()) windowStart_ = nowMs;
    return batch;
}

}  // namespace gk::realtime
