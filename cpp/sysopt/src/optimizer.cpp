#include "gk/sysopt/optimizer.hpp"

#include "gk/perf/sampler.hpp"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QStandardPaths>
#include <QStorageInfo>

#include <algorithm>
#include <functional>
#include <optional>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// windows.h first
#include <QUuid>
#include <powrprof.h>
#endif

namespace gk::sysopt {

namespace {

QString gb(qint64 bytes) { return QString::number(double(bytes) / (1024.0 * 1024 * 1024), 'f', bytes >= 100LL << 30 ? 0 : 1) + QStringLiteral(" GB"); }

Qt::CaseSensitivity pathCase() {
#ifdef _WIN32
    return Qt::CaseInsensitive;
#else
    return Qt::CaseSensitive;
#endif
}

bool under(const QString& path, const QString& folder) {
    const QString prefix = folder.endsWith(QLatin1Char('/')) ? folder : folder + QLatin1Char('/');
    return path.startsWith(prefix, pathCase());
}

bool isLink(const QFileInfo& info) { return info.isSymbolicLink() || info.isJunction(); }

// A temporary folder must be a real folder, not a drive root or the user's home, and must be named like one
// ("Temp"/"Tmp"). The Windows root comes from %TMP%/%TEMP%: if those variables point at Documents, Downloads or
// a game library (misconfiguration, or a program trying to get the user's own click to delete files), the
// folder is refused instead of having every file older than the cut-off offered for deletion.
bool safeRoot(const QString& canonical) {
    if (canonical.size() < 4 || QDir(canonical).isRoot()) return false;
    const QString name = QFileInfo(canonical).fileName();
    if (name.compare(QLatin1String("temp"), Qt::CaseInsensitive) != 0 &&
        name.compare(QLatin1String("tmp"), Qt::CaseInsensitive) != 0) {
        return false;
    }
    const QString home = QFileInfo(QDir::homePath()).canonicalFilePath();
    return canonical.compare(home, pathCase()) != 0;
}

#ifndef _WIN32
Check unavailableOnThisSystem(const QString& id, const QString& title) {
    return {id, title, QStringLiteral("unavailable"), QStringLiteral("verificado só no Windows"), QString(), QString()};
}
#endif

#ifdef _WIN32
std::optional<DWORD> regDword(HKEY root, const wchar_t* key, const wchar_t* value) {
    DWORD data = 0, size = sizeof(data);
    if (RegGetValueW(root, key, value, RRF_RT_REG_DWORD, nullptr, &data, &size) == ERROR_SUCCESS) return data;
    return std::nullopt;
}

bool regKeyExists(HKEY root, const wchar_t* key) {
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, key, 0, KEY_READ, &h) != ERROR_SUCCESS) return false;
    RegCloseKey(h);
    return true;
}

// Value names of a key, with the first byte of binary values (StartupApproved) when asked.
std::vector<std::pair<QString, int>> regValues(HKEY root, const wchar_t* key, REGSAM view = 0) {
    std::vector<std::pair<QString, int>> out;
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, key, 0, KEY_READ | view, &h) != ERROR_SUCCESS) return out;
    std::vector<wchar_t> name(16384);
    BYTE data[16];
    for (DWORD i = 0;; ++i) {
        DWORD nameLen = static_cast<DWORD>(name.size());
        DWORD dataLen = sizeof(data);
        DWORD type = 0;
        const LONG rc = RegEnumValueW(h, i, name.data(), &nameLen, nullptr, &type, data, &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA) break;
        const int first = (type == REG_BINARY && dataLen > 0 && rc == ERROR_SUCCESS) ? data[0] : -1;
        out.emplace_back(QString::fromWCharArray(name.data(), static_cast<int>(nameLen)), first);
    }
    RegCloseKey(h);
    return out;
}

Check powerCheck() {
    Check c{QStringLiteral("power_plan"), QStringLiteral("Plano de energia"), QStringLiteral("info"), QString(), QString(), QString()};
    GUID* active = nullptr;
    if (PowerGetActiveScheme(nullptr, &active) != ERROR_SUCCESS || !active) {
        c.status = QStringLiteral("unavailable");
        c.value = QStringLiteral("não foi possível ler o plano ativo");
        return c;
    }
    DWORD size = 0;
    QString name;
    if (PowerReadFriendlyName(nullptr, active, nullptr, nullptr, nullptr, &size) == ERROR_SUCCESS && size > 0) {
        std::vector<UCHAR> buffer(size + 2, 0);
        if (PowerReadFriendlyName(nullptr, active, nullptr, nullptr, buffer.data(), &size) == ERROR_SUCCESS)
            name = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buffer.data()));
    }
    const QString id = QUuid(*active).toString(QUuid::WithoutBraces).toLower();
    LocalFree(active);
    c.value = name.isEmpty() ? id : name;
    if (id == QLatin1String("a1841308-3541-4fab-bc81-f71556f20b4a")) {   // power saver
        c.status = QStringLiteral("attention");
        c.detail = QStringLiteral("O plano de economia de energia limita o processador e a placa de vídeo.");
        c.recommendation = QStringLiteral("Para jogar, use \"Equilibrado\" ou \"Alto desempenho\" em Configurações > Sistema > "
                                          "Energia e bateria (ou Painel de Controle > Opções de Energia).");
    } else if (id == QLatin1String("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c") ||
               id == QLatin1String("e9a42b02-d5df-448d-aa00-03f14749eb61")) {   // high / ultimate performance
        c.status = QStringLiteral("ok");
        c.detail = QStringLiteral("Plano de alto desempenho: o processador não é limitado para economizar energia.");
    } else {
        c.status = QStringLiteral("ok");
        c.detail = QStringLiteral("O plano \"Equilibrado\" (ou o do fabricante) atende a maioria dos jogos. Em notebooks ligados na "
                                  "tomada, \"Alto desempenho\" pode render alguns quadros a mais, com mais calor e ruído.");
    }
    SYSTEM_POWER_STATUS power{};
    if (GetSystemPowerStatus(&power) && power.ACLineStatus == 0 && power.BatteryFlag != 128) {
        c.status = QStringLiteral("attention");
        c.detail += QStringLiteral(" O computador está na bateria: o Windows reduz o desempenho para economizar.");
        c.recommendation = QStringLiteral("Ligue o notebook na tomada para jogar.");
    }
    return c;
}

Check gameModeCheck() {
    const auto v = regDword(HKEY_CURRENT_USER, L"Software\\Microsoft\\GameBar", L"AutoGameModeEnabled");
    Check c{QStringLiteral("game_mode"), QStringLiteral("Modo de Jogo do Windows"), QStringLiteral("ok"), QString(),
            QStringLiteral("Com o Modo de Jogo, o Windows dá prioridade ao jogo aberto e adia atualizações durante a partida."),
            QString()};
    if (v && *v == 0) {
        c.status = QStringLiteral("attention");
        c.value = QStringLiteral("desativado");
        c.recommendation = QStringLiteral("Ative em Configurações > Jogos > Modo de Jogo.");
    } else {
        c.value = v ? QStringLiteral("ativado") : QStringLiteral("ativado (padrão do Windows)");
    }
    return c;
}

Check captureCheck() {
    const auto historical = regDword(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR", L"HistoricalCaptureEnabled");
    Check c{QStringLiteral("background_recording"), QStringLiteral("Gravação em segundo plano (Xbox Game Bar)"), QStringLiteral("ok"),
            QStringLiteral("desativada"), QStringLiteral("A opção \"Gravar o que aconteceu\" grava o jogo continuamente, usando a placa de vídeo e o disco."),
            QString()};
    if (historical && *historical == 1) {
        c.status = QStringLiteral("attention");
        c.value = QStringLiteral("ativada");
        c.recommendation = QStringLiteral("Se você não usa, desative em Configurações > Jogos > Capturas > \"Gravar o que aconteceu\".");
    }
    return c;
}

Check gpuSchedulingCheck() {
    const auto v = regDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", L"HwSchMode");
    Check c{QStringLiteral("gpu_scheduling"), QStringLiteral("Agendamento de GPU acelerado por hardware"), QStringLiteral("info"), QString(),
            QStringLiteral("Pode reduzir um pouco a latência em placas e drivers recentes; o ganho varia de jogo para jogo."),
            QString()};
    c.value = !v ? QStringLiteral("não configurado (padrão do driver)") : (*v == 2 ? QStringLiteral("ativado") : QStringLiteral("desativado"));
    if (v && *v != 2)
        c.recommendation = QStringLiteral("Se sua placa suportar, experimente ativar em Configurações > Sistema > Tela > Elementos gráficos.");
    return c;
}

Check startupCheck() {
    QStringList enabled;
    const wchar_t* runKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t* approved = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run";
    const wchar_t* approved32 = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32";
    const wchar_t* approvedFolder = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder";
    // Entries turned off in the Task Manager keep their value with an odd first byte in StartupApproved.
    QSet<QString> disabled;
    for (HKEY root : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE})
        for (const wchar_t* key : {approved, approved32, approvedFolder})
            for (const auto& entry : regValues(root, key))
                if (entry.second >= 0 && (entry.second & 1)) disabled.insert(entry.first.toLower());
    auto add = [&](const QString& name) {
        if (!disabled.contains(name.toLower()) && !enabled.contains(name, Qt::CaseInsensitive)) enabled << name;
    };
    for (const auto& entry : regValues(HKEY_CURRENT_USER, runKey)) add(entry.first);
    for (REGSAM view : {static_cast<REGSAM>(KEY_WOW64_64KEY), static_cast<REGSAM>(KEY_WOW64_32KEY)})
        for (const auto& entry : regValues(HKEY_LOCAL_MACHINE, runKey, view)) add(entry.first);
    const QStringList startupFolders{
        QDir(qEnvironmentVariable("APPDATA")).filePath(QStringLiteral("Microsoft/Windows/Start Menu/Programs/Startup")),
        QDir(qEnvironmentVariable("PROGRAMDATA")).filePath(QStringLiteral("Microsoft/Windows/Start Menu/Programs/StartUp"))};
    for (const QString& folder : startupFolders) {
        if (qEnvironmentVariableIsEmpty("APPDATA") && folder == startupFolders.first()) continue;
        for (const QFileInfo& f : QDir(folder).entryInfoList(QDir::Files | QDir::NoDotAndDotDot))
            if (f.fileName().compare(QLatin1String("desktop.ini"), Qt::CaseInsensitive) != 0) add(f.fileName());
    }
    enabled.sort(Qt::CaseInsensitive);
    Check c{QStringLiteral("startup_programs"), QStringLiteral("Programas que iniciam com o Windows"), QStringLiteral("ok"),
            QStringLiteral("%1 programa(s)").arg(enabled.size()), enabled.mid(0, 40).join(QStringLiteral(", ")), QString()};
    if (enabled.size() > 12) {
        c.status = QStringLiteral("attention");
        c.recommendation = QStringLiteral("Muitos programas abertos em segundo plano disputam memória e processador com o jogo. "
                                          "Desative os que você não usa em Gerenciador de Tarefas > Aplicativos de inicialização.");
    } else if (!enabled.isEmpty()) {
        c.status = QStringLiteral("info");
    }
    return c;
}

Check rebootCheck() {
    const bool pending =
        regKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired") ||
        regKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending");
    Check c{QStringLiteral("pending_reboot"), QStringLiteral("Reinicialização pendente"), QStringLiteral("ok"),
            pending ? QStringLiteral("sim") : QStringLiteral("não"), QString(), QString()};
    if (pending) {
        c.status = QStringLiteral("attention");
        c.detail = QStringLiteral("Atualizações do Windows esperam uma reinicialização para terminar; até lá elas podem continuar "
                                  "trabalhando em segundo plano.");
        c.recommendation = QStringLiteral("Reinicie o computador antes de jogar.");
    }
    return c;
}
#endif

Check memoryCheck() {
    const gk::perf::MemoryStatus m = gk::perf::memoryStatus();
    Check c{QStringLiteral("memory"), QStringLiteral("Memória (RAM)"), QStringLiteral("ok"), QString(), QString(), QString()};
    if (m.total <= 0) {
        c.status = QStringLiteral("unavailable");
        c.value = QStringLiteral("não foi possível ler");
        return c;
    }
    const double freeShare = double(m.available) / double(m.total);
    c.value = QStringLiteral("%1 livres de %2").arg(gb(m.available), gb(m.total));
    if (freeShare < 0.15) {
        c.status = QStringLiteral("attention");
        c.detail = QStringLiteral("Pouca memória livre agora: o jogo pode travar ou usar o disco no lugar da memória.");
        c.recommendation = QStringLiteral("Feche os programas que mais usam memória (veja a página Desempenho) antes de jogar.");
    } else if (m.total < 8LL * 1024 * 1024 * 1024 - 512LL * 1024 * 1024) {
        c.status = QStringLiteral("info");
        c.detail = QStringLiteral("Menos de 8 GB de memória: jogos atuais costumam pedir 8 a 16 GB.");
    }
    return c;
}

QList<Check> diskChecks(const QStringList& folders) {
    QList<QStorageInfo> volumes{QStorageInfo::root()};
    for (const QString& f : folders) {
        const QStorageInfo v(f);
        if (v.isValid() && std::none_of(volumes.begin(), volumes.end(), [&](const QStorageInfo& o) { return o.rootPath() == v.rootPath(); }))
            volumes << v;
    }
    QList<Check> out;
    for (const QStorageInfo& v : volumes) {
        if (!v.isValid() || !v.isReady() || v.bytesTotal() <= 0) continue;
        const QString where = QDir::toNativeSeparators(v.rootPath());
        Check c{QStringLiteral("disk:") + v.rootPath(), QStringLiteral("Espaço livre em %1").arg(where), QStringLiteral("ok"),
                QStringLiteral("%1 livres de %2 (%3%)")
                    .arg(gb(v.bytesAvailable()), gb(v.bytesTotal()))
                    .arg(qRound(100.0 * double(v.bytesAvailable()) / double(v.bytesTotal()))),
                QString(), QString()};
        if (double(v.bytesAvailable()) / double(v.bytesTotal()) < 0.10 || v.bytesAvailable() < 15LL * 1024 * 1024 * 1024) {
            c.status = QStringLiteral("attention");
            c.detail = QStringLiteral("Pouco espaço livre: atualizações de jogos falham e o Windows fica mais lento com o disco cheio.");
            c.recommendation = QStringLiteral("Desinstale jogos que não usa, limpe os arquivos temporários abaixo ou use a Limpeza "
                                              "de Disco do Windows.");
        }
        out << c;
    }
    return out;
}

}  // namespace

QJsonObject toJson(const Check& c) {
    return {{"id", c.id}, {"title", c.title}, {"status", c.status}, {"value", c.value}, {"detail", c.detail},
            {"recommendation", c.recommendation}};
}

QList<Check> diagnose(const QStringList& folders) {
    QList<Check> checks;
#ifdef _WIN32
    checks << powerCheck() << gameModeCheck() << captureCheck() << gpuSchedulingCheck();
#else
    checks << unavailableOnThisSystem(QStringLiteral("power_plan"), QStringLiteral("Plano de energia"))
           << unavailableOnThisSystem(QStringLiteral("game_mode"), QStringLiteral("Modo de Jogo do Windows"))
           << unavailableOnThisSystem(QStringLiteral("background_recording"), QStringLiteral("Gravação em segundo plano (Xbox Game Bar)"))
           << unavailableOnThisSystem(QStringLiteral("gpu_scheduling"), QStringLiteral("Agendamento de GPU acelerado por hardware"));
#endif
    checks << memoryCheck();
    checks += diskChecks(folders);
#ifdef _WIN32
    checks << startupCheck() << rebootCheck();
#else
    checks << unavailableOnThisSystem(QStringLiteral("startup_programs"), QStringLiteral("Programas que iniciam com o Windows"))
           << unavailableOnThisSystem(QStringLiteral("pending_reboot"), QStringLiteral("Reinicialização pendente"));
#endif
    return checks;
}

// ================================================================================== temporary files
QStringList defaultTempRoots(const QString& dataDir) {
    QStringList roots;
#ifdef _WIN32
    std::vector<wchar_t> buffer(MAX_PATH + 2);
    const DWORD n = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());   // %TMP% / %TEMP% of this user
    if (n > 0 && n < buffer.size()) roots << QDir::cleanPath(QDir::fromNativeSeparators(QString::fromWCharArray(buffer.data(), static_cast<int>(n))));
#endif
    if (!dataDir.isEmpty()) roots << QDir(dataDir).filePath(QStringLiteral("temp"));
    return roots;
}

QJsonObject toJson(const TempPlan& p) {
    QJsonArray roots;
    for (const QString& r : p.roots) roots.append(QDir::toNativeSeparators(r));
    return {{"roots", roots},        {"min_age_hours", p.minAgeHours}, {"files", static_cast<qint64>(p.files.size())},
            {"bytes", p.bytes},       {"dirs", static_cast<qint64>(p.dirs.size())}, {"recent", p.recent},
            {"links", p.links},       {"unreadable", p.unreadable}, {"truncated", p.truncated}};
}

QJsonObject toJson(const CleanResult& r) {
    return {{"deleted", r.deleted}, {"bytes_freed", r.bytesFreed}, {"in_use", r.inUse}, {"changed", r.changed},
            {"dirs_removed", r.dirsRemoved}, {"problems", QJsonArray::fromStringList(r.problems)}};
}

TempPlan analyzeTemp(const QStringList& roots, int minAgeHours, const std::atomic<bool>* cancel, int maxFiles) {
    TempPlan plan;
    plan.minAgeHours = std::clamp(minAgeHours, 1, 24 * 365);
    const qint64 cutoff = QDateTime::currentMSecsSinceEpoch() - qint64(plan.minAgeHours) * 3600 * 1000;
    auto cancelled = [cancel] { return cancel && cancel->load(); };

    std::function<void(const QString&, int)> walk = [&](const QString& dir, int depth) {
        if (depth > 64 || plan.truncated || cancelled()) return;
        const QDir d(dir);
        if (!d.isReadable()) {
            ++plan.unreadable;
            return;
        }
        const QFileInfoList entries = d.entryInfoList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System, QDir::NoSort);
        for (const QFileInfo& e : entries) {
            if (plan.truncated || cancelled()) return;
            if (isLink(e)) {
                ++plan.links;   // never followed, never deleted
                continue;
            }
            if (e.isDir()) {
                walk(e.absoluteFilePath(), depth + 1);
                if (e.lastModified().toMSecsSinceEpoch() < cutoff) plan.dirs << e.absoluteFilePath();   // children first
                continue;
            }
            if (!e.isFile()) continue;
            const qint64 mtime = e.lastModified().toMSecsSinceEpoch();
            if (mtime >= cutoff) {
                ++plan.recent;   // may belong to an installer or a game running now
                continue;
            }
            plan.files.append({e.absoluteFilePath(), e.size(), mtime});
            plan.bytes += e.size();
            if (plan.files.size() >= maxFiles) plan.truncated = true;
        }
    };
    for (const QString& r : roots) {
        const QFileInfo info(r);
        if (!info.isDir() || isLink(info)) continue;
        const QString canonical = info.canonicalFilePath();
        if (canonical.isEmpty() || !safeRoot(canonical) || plan.roots.contains(canonical, pathCase())) continue;
        plan.roots << canonical;
        walk(canonical, 0);
    }
    return plan;
}

CleanResult cleanTemp(const TempPlan& plan, const std::atomic<bool>* cancel) {
    CleanResult r;
    auto inside = [&plan](const QString& canonical) {
        return std::any_of(plan.roots.begin(), plan.roots.end(), [&](const QString& root) { return under(canonical, root); });
    };
    for (const TempFile& f : plan.files) {
        if (cancel && cancel->load()) break;
        const QFileInfo fi(f.path);
        if (!fi.exists() && !fi.isSymbolicLink()) continue;   // already gone
        // Replaced by a link, modified, or moved out of the temporary folder (a parent swapped for a junction)
        // since the analysis: kept.
        if (isLink(fi) || !fi.isFile() || fi.size() != f.size || fi.lastModified().toMSecsSinceEpoch() != f.mtimeMs ||
            !inside(fi.canonicalFilePath())) {
            ++r.changed;
            continue;
        }
        QFile file(f.path);
        if (file.remove()) {
            ++r.deleted;
            r.bytesFreed += f.size;
        } else {
            ++r.inUse;
            if (r.problems.size() < 20) r.problems << QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(f.path), file.errorString());
        }
    }
    for (const QString& d : plan.dirs) {
        if (cancel && cancel->load()) break;
        const QFileInfo di(d);
        if (!di.isDir() || isLink(di) || !inside(di.canonicalFilePath())) continue;
        if (QDir().rmdir(d)) ++r.dirsRemoved;   // only succeeds when the folder is empty
    }
    return r;
}

}  // namespace gk::sysopt
