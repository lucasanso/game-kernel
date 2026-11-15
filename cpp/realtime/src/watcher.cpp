#include "gk/realtime/watcher.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMetaObject>

#include <algorithm>
#include <atomic>
#include <map>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#elif defined(__linux__)
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>
#endif

namespace gk::realtime {

namespace {

Qt::CaseSensitivity pathCase() {
#ifdef _WIN32
    return Qt::CaseInsensitive;
#else
    return Qt::CaseSensitive;
#endif
}

bool isUnder(const QString& path, const QString& folder) {
    if (path.compare(folder, pathCase()) == 0) return true;
    const QString prefix = folder.endsWith(QLatin1Char('/')) ? folder : folder + QLatin1Char('/');
    return path.startsWith(prefix, pathCase());
}

using Refusal = DirectoryWatcher::Refusal;

// Absolute, cleaned, existing folders; folders inside another requested folder are already covered by it.
QStringList normalizedRoots(const QStringList& requested, QList<Refusal>* refused) {
    QStringList roots;
    for (const QString& r : requested) {
        if (r.trimmed().isEmpty()) continue;
        const QFileInfo info(r);
        const QString clean = DirectoryWatcher::cleanFolder(r);
        if (!info.exists()) {
            refused->append({clean, QStringLiteral("a pasta não existe")});
            continue;
        }
        if (!info.isDir()) {
            refused->append({clean, QStringLiteral("não é uma pasta")});
            continue;
        }
        if (!roots.contains(clean, pathCase())) roots.append(clean);
    }
    std::sort(roots.begin(), roots.end(), [](const QString& a, const QString& b) { return a.size() < b.size(); });
    QStringList out;
    for (const QString& r : roots) {
        if (std::none_of(out.begin(), out.end(), [&](const QString& o) { return isUnder(r, o); })) out.append(r);
    }
    return out;
}

}  // namespace

struct DirectoryWatcher::Impl {
    explicit Impl(DirectoryWatcher* o) : owner(o) {}

    DirectoryWatcher* owner;
    QStringList roots;
    std::thread thread;
    std::atomic<bool> active{false};

    void post(QList<Change> batch) {
        if (batch.isEmpty()) return;
        QMetaObject::invokeMethod(owner, [o = owner, b = std::move(batch)] { emit o->changes(b); }, Qt::QueuedConnection);
    }
    void postOverflow(const QString& root) {
        QMetaObject::invokeMethod(owner, [o = owner, root] { emit o->overflow(root); }, Qt::QueuedConnection);
    }
    void postFailed(const QString& root, const QString& message) {
        QMetaObject::invokeMethod(owner, [o = owner, root, message] { emit o->failed(root, message); }, Qt::QueuedConnection);
    }

#ifdef _WIN32
    struct Root {
        QString path;
        HANDLE dir = INVALID_HANDLE_VALUE;
        OVERLAPPED ov{};
        std::vector<DWORD> buffer = std::vector<DWORD>(16384);   // 64 KiB, DWORD-aligned (network shares cap at 64 KiB)
        bool pending = false;
    };
    static constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE |
                                     FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION;
    HANDLE stopEvent = nullptr;
    std::vector<std::unique_ptr<Root>> watched;

    static QString errorText(DWORD code) {
        wchar_t* buf = nullptr;
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                       code, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
        const QString text = buf ? QString::fromWCharArray(buf).trimmed() : QString();
        if (buf) LocalFree(buf);
        return QStringLiteral("%1 (código %2)").arg(text).arg(code);
    }

    bool issue(Root& r) {
        ResetEvent(r.ov.hEvent);
        r.pending = ReadDirectoryChangesW(r.dir, r.buffer.data(), static_cast<DWORD>(r.buffer.size() * sizeof(DWORD)), TRUE,
                                          kFilter, nullptr, &r.ov, nullptr) != FALSE;
        return r.pending;
    }

    static void close(Root& r) {
        if (r.dir != INVALID_HANDLE_VALUE) {
            if (r.pending) {
                CancelIoEx(r.dir, &r.ov);
                DWORD ignored = 0;
                GetOverlappedResult(r.dir, &r.ov, &ignored, TRUE);
                r.pending = false;
            }
            CloseHandle(r.dir);
            r.dir = INVALID_HANDLE_VALUE;
        }
        if (r.ov.hEvent) {
            CloseHandle(r.ov.hEvent);
            r.ov.hEvent = nullptr;
        }
    }

    static ChangeKind kindOf(DWORD action) {
        switch (action) {
            case FILE_ACTION_ADDED: return ChangeKind::Added;
            case FILE_ACTION_REMOVED: return ChangeKind::Removed;
            case FILE_ACTION_RENAMED_OLD_NAME: return ChangeKind::RenamedFrom;
            case FILE_ACTION_RENAMED_NEW_NAME: return ChangeKind::RenamedTo;
            default: return ChangeKind::Modified;
        }
    }

    // ReadDirectoryChangesW may report 8.3 short names; the long name is what the user and the scanner see.
    static QString longName(const QString& path) {
        const std::wstring in = QDir::toNativeSeparators(path).toStdWString();
        std::vector<wchar_t> out(32768);
        const DWORD n = GetLongPathNameW(in.c_str(), out.data(), static_cast<DWORD>(out.size()));
        if (n == 0 || n >= out.size()) return path;
        return QDir::fromNativeSeparators(QString::fromWCharArray(out.data(), static_cast<int>(n)));
    }

    void parse(const Root& r, DWORD bytes) {
        QList<Change> batch;
        const auto* base = reinterpret_cast<const std::byte*>(r.buffer.data());
        std::size_t offset = 0;
        constexpr std::size_t header = offsetof(FILE_NOTIFY_INFORMATION, FileName);
        while (offset + header <= bytes) {
            const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(base + offset);
            if (offset + header + info->FileNameLength > bytes) break;
            QString rel = QString::fromWCharArray(info->FileName, static_cast<int>(info->FileNameLength / sizeof(WCHAR)));
            rel.replace(QLatin1Char('\\'), QLatin1Char('/'));
            Change c;
            c.kind = kindOf(info->Action);
            c.path = r.path + QLatin1Char('/') + rel;
            if (rel.contains(QLatin1Char('~')) && c.kind != ChangeKind::Removed && c.kind != ChangeKind::RenamedFrom)
                c.path = longName(c.path);
            batch.append(c);
            if (info->NextEntryOffset == 0) break;
            offset += info->NextEntryOffset;
        }
        post(std::move(batch));
    }

    QList<Refusal> open(const QStringList& folders) {
        QList<Refusal> errors;
        stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        for (const QString& f : folders) {
            if (watched.size() >= static_cast<std::size_t>(MAXIMUM_WAIT_OBJECTS - 1)) {
                errors.append({f, QStringLiteral("limite de %1 pastas observadas").arg(MAXIMUM_WAIT_OBJECTS - 1)});
                continue;
            }
            auto r = std::make_unique<Root>();
            r->path = f;
            r->dir = CreateFileW(QDir::toNativeSeparators(f).toStdWString().c_str(), FILE_LIST_DIRECTORY,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
            if (r->dir == INVALID_HANDLE_VALUE) {
                errors.append({f, errorText(GetLastError())});
                continue;
            }
            r->ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!r->ov.hEvent || !issue(*r)) {
                errors.append({f, errorText(GetLastError())});
                close(*r);
                continue;
            }
            roots.append(f);
            watched.push_back(std::move(r));
        }
        return errors;
    }

    void run() {
        for (;;) {
            std::vector<HANDLE> handles{stopEvent};
            std::vector<Root*> map;
            for (auto& r : watched) {
                if (r->dir != INVALID_HANDLE_VALUE) {
                    handles.push_back(r->ov.hEvent);
                    map.push_back(r.get());
                }
            }
            const DWORD w = WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE, INFINITE);
            if (w == WAIT_OBJECT_0) return;
            if (w <= WAIT_OBJECT_0 || w >= WAIT_OBJECT_0 + handles.size()) {
                const QString why = errorText(GetLastError());
                for (Root* r : map) postFailed(r->path, why);
                return;
            }
            Root& r = *map[w - WAIT_OBJECT_0 - 1];
            DWORD bytes = 0;
            r.pending = false;
            if (!GetOverlappedResult(r.dir, &r.ov, &bytes, FALSE)) {
                const DWORD e = GetLastError();
                if (e == ERROR_NOTIFY_ENUM_DIR) {
                    postOverflow(r.path);
                } else {
                    postFailed(r.path, errorText(e));
                    close(r);
                    continue;
                }
            } else if (bytes == 0) {
                postOverflow(r.path);   // more changes than the buffer holds: the caller rescans the folder
            } else {
                parse(r, bytes);
            }
            if (!issue(r)) {
                postFailed(r.path, QStringLiteral("a pasta deixou de poder ser observada: %1").arg(errorText(GetLastError())));
                close(r);
            }
        }
    }

    void wake() {
        if (stopEvent) SetEvent(stopEvent);
    }

    void closeAll() {
        for (auto& r : watched) close(*r);
        watched.clear();
        if (stopEvent) CloseHandle(stopEvent);
        stopEvent = nullptr;
    }
#elif defined(__linux__)
    static constexpr std::uint32_t kMask = IN_CREATE | IN_CLOSE_WRITE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE |
                                           IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK;
    int fd = -1;
    int wakeFd = -1;
    std::map<int, QString> wdPath;   // watch descriptor -> directory
    std::map<int, QString> wdRoot;   // watch descriptor -> watched root it belongs to

    static QString errnoText(int e) {
        if (e == ENOSPC) return QStringLiteral("limite de pastas observadas do sistema atingido (fs.inotify.max_user_watches)");
        return QString::fromLocal8Bit(std::strerror(e));
    }

    // Adds a watch for `dir` and every directory below it (symbolic links are not followed).
    QString addTree(const QString& dir, const QString& root) {
        namespace fs = std::filesystem;
        auto add = [&](const QString& d) -> QString {
            const int wd = inotify_add_watch(fd, QFile::encodeName(d).constData(), kMask);
            if (wd < 0) return QStringLiteral("%1: %2").arg(d, errnoText(errno));
            wdPath[wd] = d;
            wdRoot[wd] = root;
            return {};
        };
        if (QString e = add(dir); !e.isEmpty()) return e;
        std::error_code ec;
        fs::recursive_directory_iterator it(fs::path(QFile::encodeName(dir).toStdString()),
                                            fs::directory_options::skip_permission_denied, ec);
        for (; !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            std::error_code sec;
            if (it->is_symlink(sec)) {
                it.disable_recursion_pending();
                continue;
            }
            if (it->is_directory(sec)) {
                if (QString e = add(QFile::decodeName(it->path().c_str())); !e.isEmpty()) return e;
            }
        }
        return {};
    }

    void forgetTree(const QString& dir) {
        for (auto it = wdPath.begin(); it != wdPath.end();) {
            if (isUnder(it->second, dir)) {
                inotify_rm_watch(fd, it->first);
                wdRoot.erase(it->first);
                it = wdPath.erase(it);
            } else {
                ++it;
            }
        }
    }

    QList<Refusal> open(const QStringList& folders) {
        QList<Refusal> errors;
        fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        wakeFd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (fd < 0 || wakeFd < 0) {
            const QString why = errnoText(errno);
            for (const QString& f : folders) errors.append({f, why});
            return errors;
        }
        for (const QString& f : folders) {
            if (QString e = addTree(f, f); !e.isEmpty()) {
                forgetTree(f);
                errors.append({f, e});
                continue;
            }
            roots.append(f);
        }
        return errors;
    }

    void run() {
        QStringList live = roots;   // `roots` stays as started: it is read from the owner's thread
        alignas(inotify_event) char buf[64 * 1024];
        pollfd fds[2] = {{fd, POLLIN, 0}, {wakeFd, POLLIN, 0}};
        for (;;) {
            if (poll(fds, 2, -1) < 0) {
                if (errno == EINTR) continue;
                for (const QString& r : live) postFailed(r, errnoText(errno));
                return;
            }
            if (fds[1].revents) return;
            const ssize_t len = read(fd, buf, sizeof buf);
            if (len <= 0) {
                if (len < 0 && (errno == EAGAIN || errno == EINTR)) continue;
                for (const QString& r : live) postFailed(r, errnoText(errno));
                return;
            }
            QList<Change> batch;
            for (char* p = buf; p < buf + len;) {
                const auto* ev = reinterpret_cast<const inotify_event*>(p);
                p += sizeof(inotify_event) + ev->len;
                if (ev->mask & IN_Q_OVERFLOW) {
                    for (const QString& r : live) postOverflow(r);
                    continue;
                }
                const auto it = wdPath.find(ev->wd);
                if (it == wdPath.end()) continue;
                const QString dir = it->second;
                const QString root = wdRoot[ev->wd];
                if (ev->mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF)) {
                    if (dir == root) {
                        postFailed(root, QStringLiteral("a pasta foi removida, movida ou desmontada"));
                        forgetTree(root);
                        live.removeAll(root);
                    }
                    continue;
                }
                if (ev->len == 0) continue;
                Change c;
                c.path = dir + QLatin1Char('/') + QFile::decodeName(ev->name);
                c.directory = (ev->mask & IN_ISDIR) != 0;
                if (ev->mask & IN_CREATE) c.kind = ChangeKind::Added;
                else if (ev->mask & IN_MOVED_TO) c.kind = ChangeKind::RenamedTo;
                else if (ev->mask & IN_MOVED_FROM) c.kind = ChangeKind::RenamedFrom;
                else if (ev->mask & IN_DELETE) c.kind = ChangeKind::Removed;
                else c.kind = ChangeKind::Modified;
                if (c.directory && (c.kind == ChangeKind::Added || c.kind == ChangeKind::RenamedTo)) {
                    // Files created inside it before the watch existed are covered: the folder itself is reported
                    // and scanned as a whole.
                    if (const QString e = addTree(c.path, root); !e.isEmpty()) postFailed(c.path, e);
                } else if (c.directory && c.kind == ChangeKind::RenamedFrom) {
                    forgetTree(c.path);
                }
                batch.append(c);
            }
            post(std::move(batch));
        }
    }

    void wake() {
        if (wakeFd >= 0) {
            const std::uint64_t one = 1;
            [[maybe_unused]] const auto n = ::write(wakeFd, &one, sizeof one);
        }
    }

    void closeAll() {
        if (fd >= 0) ::close(fd);
        if (wakeFd >= 0) ::close(wakeFd);
        fd = wakeFd = -1;
        wdPath.clear();
        wdRoot.clear();
    }
#else
    QList<Refusal> open(const QStringList& folders) {
        QList<Refusal> errors;
        for (const QString& f : folders) errors.append({f, QStringLiteral("proteção em tempo real não suportada nesta plataforma")});
        return errors;
    }
    void run() {}
    void wake() {}
    void closeAll() {}
#endif
};

DirectoryWatcher::DirectoryWatcher(QObject* parent) : QObject(parent), impl_(std::make_unique<Impl>(this)) {
    qRegisterMetaType<gk::realtime::Change>();
    qRegisterMetaType<QList<gk::realtime::Change>>();
}

DirectoryWatcher::~DirectoryWatcher() { stop(); }

bool DirectoryWatcher::supported() {
#if defined(_WIN32) || defined(__linux__)
    return true;
#else
    return false;
#endif
}

QString DirectoryWatcher::cleanFolder(const QString& folder) {
    return QDir::cleanPath(QDir::fromNativeSeparators(QFileInfo(folder).absoluteFilePath()));
}

QList<DirectoryWatcher::Refusal> DirectoryWatcher::start(const QStringList& requested) {
    stop();
    QList<Refusal> errors;
    const QStringList folders = normalizedRoots(requested, &errors);
    errors += impl_->open(folders);
    if (impl_->roots.isEmpty()) {
        impl_->closeAll();
        return errors;
    }
    impl_->active = true;
    impl_->thread = std::thread([impl = impl_.get()] { impl->run(); });
    return errors;
}

void DirectoryWatcher::stop() {
    if (impl_->thread.joinable()) {
        impl_->wake();
        impl_->thread.join();
    }
    impl_->closeAll();
    impl_->roots.clear();
    impl_->active = false;
}

bool DirectoryWatcher::active() const { return impl_->active; }

QStringList DirectoryWatcher::roots() const { return impl_->active ? impl_->roots : QStringList{}; }

}  // namespace gk::realtime
