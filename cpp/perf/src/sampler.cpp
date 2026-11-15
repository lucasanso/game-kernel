#include "gk/perf/sampler.hpp"

#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QHash>
#include <QJsonArray>
#include <QRegularExpression>
#include <QThread>

#include <algorithm>
#include <cstdint>
#include <map>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// windows.h first
#include <dxgi1_4.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <psapi.h>
#include <tlhelp32.h>
#else
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <unistd.h>
#endif

namespace gk::perf {

namespace {

double clampPercent(double v) { return std::clamp(v, 0.0, 100.0); }

// Busiest first; unknown values (-1) never make the list.
QList<ProcessUsage> top(QList<ProcessUsage> all, int n, double ProcessUsage::*by) {
    all.erase(std::remove_if(all.begin(), all.end(), [by](const ProcessUsage& p) { return p.*by <= 0; }), all.end());
    std::sort(all.begin(), all.end(), [by](const ProcessUsage& a, const ProcessUsage& b) { return a.*by > b.*by; });
    return all.mid(0, n);
}

QList<ProcessUsage> topMemory(QList<ProcessUsage> all, int n) {
    std::sort(all.begin(), all.end(), [](const ProcessUsage& a, const ProcessUsage& b) { return a.memoryBytes > b.memoryBytes; });
    return all.mid(0, n);
}

QJsonObject processJson(const ProcessUsage& p) {
    return {{"pid", p.pid},
            {"name", p.name},
            {"cpu_percent", p.cpuPercent >= 0 ? QJsonValue(p.cpuPercent) : QJsonValue(QJsonValue::Null)},
            {"gpu_percent", p.gpuPercent >= 0 ? QJsonValue(p.gpuPercent) : QJsonValue(QJsonValue::Null)},
            {"memory_bytes", p.memoryBytes}};
}

QJsonValue maybe(double v) { return v >= 0 ? QJsonValue(v) : QJsonValue(QJsonValue::Null); }
QJsonValue maybe(qint64 v) { return v >= 0 ? QJsonValue(v) : QJsonValue(QJsonValue::Null); }

}  // namespace

QJsonObject toJson(const Sample& s) {
    QJsonArray gpus, cpu, mem, gpu;
    for (const GpuAdapter& g : s.gpus) {
        gpus.append(QJsonObject{{"name", g.name},
                                {"luid", g.luid},
                                {"utilization", maybe(g.utilization)},
                                {"dedicated_total", g.dedicatedTotal},
                                {"dedicated_used", maybe(g.dedicatedUsed)},
                                {"shared_used", maybe(g.sharedUsed)}});
    }
    for (const auto& p : s.topCpu) cpu.append(processJson(p));
    for (const auto& p : s.topMemory) mem.append(processJson(p));
    for (const auto& p : s.topGpu) gpu.append(processJson(p));
    return {{"at_ms", s.atMs},
            {"logical_cpus", s.logicalCpus},
            {"cpu_percent", maybe(s.cpuPercent)},
            {"memory_total", s.memTotal},
            {"memory_available", s.memAvailable},
            {"disk_read_bps", maybe(s.diskReadBps)},
            {"disk_write_bps", maybe(s.diskWriteBps)},
            {"gpus", gpus},
            {"top_cpu", cpu},
            {"top_memory", mem},
            {"top_gpu", gpu},
            {"self", processJson(s.self)},
            {"processes", s.processes},
            {"unmeasured", s.unmeasured},
            {"unavailable", QJsonArray::fromStringList(s.unavailable)}};
}

#ifdef _WIN32
// ============================================================================================ Windows
MemoryStatus memoryStatus() {
    MemoryStatus m;
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        m.total = static_cast<qint64>(ms.ullTotalPhys);
        m.available = static_cast<qint64>(ms.ullAvailPhys);
    }
    return m;
}

namespace {

quint64 ft(const FILETIME& f) { return (quint64(f.dwHighDateTime) << 32) | f.dwLowDateTime; }

// Formatted values of a wildcard counter, by instance name.
std::vector<std::pair<QString, double>> counterArray(PDH_HCOUNTER counter) {
    std::vector<std::pair<QString, double>> out;
    if (!counter) return out;
    DWORD bytes = 0, count = 0;
    if (PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &bytes, &count, nullptr) != PDH_MORE_DATA)
        return out;
    std::vector<std::uint64_t> buffer((bytes + sizeof(std::uint64_t) - 1) / sizeof(std::uint64_t) + 1);
    auto* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(buffer.data());
    if (PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &bytes, &count, items) != ERROR_SUCCESS)
        return out;
    for (DWORD i = 0; i < count; ++i) {
        const DWORD st = items[i].FmtValue.CStatus;
        if (st == PDH_CSTATUS_VALID_DATA || st == PDH_CSTATUS_NEW_DATA)
            out.emplace_back(QString::fromWCharArray(items[i].szName), items[i].FmtValue.doubleValue);
    }
    return out;
}

double counterValue(PDH_HCOUNTER counter) {
    if (!counter) return -1;
    PDH_FMT_COUNTERVALUE v{};
    if (PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, nullptr, &v) != ERROR_SUCCESS) return -1;
    if (v.CStatus != PDH_CSTATUS_VALID_DATA && v.CStatus != PDH_CSTATUS_NEW_DATA) return -1;
    return std::max(0.0, v.doubleValue);
}

}  // namespace

struct Sampler::Impl {
    struct Proc {
        quint64 cpu = 0, created = 0;
    };

    int topCount;
    QElapsedTimer clock;
    qint64 lastMs = -1;
    quint64 lastIdle = 0, lastKernel = 0, lastUser = 0;
    bool haveCpu = false;
    QHash<qint64, Proc> procs;
    PDH_HQUERY query = nullptr;
    PDH_HCOUNTER diskRead = nullptr, diskWrite = nullptr, gpuEngine = nullptr, gpuDedicated = nullptr, gpuShared = nullptr;
    bool primed = false;
    QList<GpuAdapter> adapters;
    QString adapterProblem;

    explicit Impl(int n) : topCount(n) {
        clock.start();
        if (PdhOpenQueryW(nullptr, 0, &query) != ERROR_SUCCESS) {
            query = nullptr;
        } else {
            // English counter names: the same on every Windows language.
            auto add = [this](const wchar_t* path, PDH_HCOUNTER* c) {
                if (PdhAddEnglishCounterW(query, path, 0, c) != ERROR_SUCCESS) *c = nullptr;
            };
            add(L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec", &diskRead);
            add(L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec", &diskWrite);
            add(L"\\GPU Engine(*)\\Utilization Percentage", &gpuEngine);
            add(L"\\GPU Adapter Memory(*)\\Dedicated Usage", &gpuDedicated);
            add(L"\\GPU Adapter Memory(*)\\Shared Usage", &gpuShared);
            primed = PdhCollectQueryData(query) == ERROR_SUCCESS;   // rate counters need two collections
        }
        loadAdapters();
    }

    ~Impl() {
        if (query) PdhCloseQuery(query);
    }

    void loadAdapters() {
        IDXGIFactory1* factory = nullptr;
        if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&factory))) || !factory) {
            adapterProblem = QStringLiteral("o DirectX (DXGI) não informou as placas de vídeo");
            return;
        }
        for (UINT i = 0;; ++i) {
            IDXGIAdapter1* adapter = nullptr;
            if (factory->EnumAdapters1(i, &adapter) == DXGI_ERROR_NOT_FOUND || !adapter) break;
            DXGI_ADAPTER_DESC1 d{};
            if (SUCCEEDED(adapter->GetDesc1(&d)) && !(d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) {
                GpuAdapter g;
                g.name = QString::fromWCharArray(d.Description).trimmed();
                g.dedicatedTotal = static_cast<qint64>(d.DedicatedVideoMemory);
                g.luid = QString::asprintf("luid_0x%08x_0x%08x", static_cast<unsigned>(d.AdapterLuid.HighPart),
                                           static_cast<unsigned>(d.AdapterLuid.LowPart));
                if (std::none_of(adapters.begin(), adapters.end(), [&](const GpuAdapter& a) { return a.luid == g.luid; }))
                    adapters << g;
            }
            adapter->Release();
        }
        factory->Release();
        if (adapters.isEmpty()) adapterProblem = QStringLiteral("nenhuma placa de vídeo física encontrada");
    }

    Sample sample() {
        Sample s;
        s.atMs = QDateTime::currentMSecsSinceEpoch();
        s.logicalCpus = static_cast<int>(std::max<DWORD>(1, GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)));
        const qint64 now = clock.elapsed();
        const qint64 elapsedMs = lastMs < 0 ? -1 : now - lastMs;
        lastMs = now;

        FILETIME idle{}, kernel{}, user{};
        if (GetSystemTimes(&idle, &kernel, &user)) {
            const quint64 i = ft(idle), k = ft(kernel), u = ft(user);   // kernel time includes idle time
            if (haveCpu) {
                const quint64 total = (k - lastKernel) + (u - lastUser);
                const quint64 idleDelta = std::min(i - lastIdle, total);
                if (total > 0) s.cpuPercent = clampPercent(100.0 * double(total - idleDelta) / double(total));
            }
            lastIdle = i;
            lastKernel = k;
            lastUser = u;
            haveCpu = true;
        }
        const MemoryStatus mem = memoryStatus();
        s.memTotal = mem.total;
        s.memAvailable = mem.available;

        // GPU engines and memory, disk throughput.
        QHash<qint64, double> processGpu;
        QList<GpuAdapter> gpus = adapters;
        if (query) {
            const bool collected = PdhCollectQueryData(query) == ERROR_SUCCESS;
            if (collected && primed) {
                s.diskReadBps = counterValue(diskRead);
                s.diskWriteBps = counterValue(diskWrite);
                static const QRegularExpression engineRe(
                    QStringLiteral("^pid_(\\d+)_(luid_0x[0-9a-f]+_0x[0-9a-f]+)_phys_\\d+_eng_\\d+_engtype_(.*)$"),
                    QRegularExpression::CaseInsensitiveOption);
                std::map<QString, std::map<QString, double>> byAdapter;   // luid -> engine type -> sum
                std::map<qint64, std::map<QString, double>> byProcess;    // pid -> engine type -> sum
                for (const auto& [name, value] : counterArray(gpuEngine)) {
                    const auto m = engineRe.match(name);
                    if (!m.hasMatch()) continue;
                    byAdapter[m.captured(2).toLower()][m.captured(3)] += value;
                    byProcess[m.captured(1).toLongLong()][m.captured(3)] += value;
                }
                for (const auto& [pid, types] : byProcess) {
                    double busiest = 0;
                    for (const auto& [type, v] : types) busiest = std::max(busiest, v);
                    processGpu.insert(pid, clampPercent(busiest));
                }
                static const QRegularExpression memoryRe(QStringLiteral("^(luid_0x[0-9a-f]+_0x[0-9a-f]+)_phys_\\d+$"),
                                                         QRegularExpression::CaseInsensitiveOption);
                std::map<QString, double> dedicated, shared;
                for (const auto& [name, value] : counterArray(gpuDedicated))
                    if (const auto m = memoryRe.match(name); m.hasMatch()) dedicated[m.captured(1).toLower()] += value;
                for (const auto& [name, value] : counterArray(gpuShared))
                    if (const auto m = memoryRe.match(name); m.hasMatch()) shared[m.captured(1).toLower()] += value;
                for (GpuAdapter& g : gpus) {
                    if (const auto it = byAdapter.find(g.luid); it != byAdapter.end()) {
                        double busiest = 0;
                        for (const auto& [type, v] : it->second) busiest = std::max(busiest, v);
                        g.utilization = clampPercent(busiest);
                    } else if (gpuEngine) {
                        g.utilization = 0;   // no engine of this adapter is in use by any process
                    }
                    if (const auto it = dedicated.find(g.luid); it != dedicated.end()) g.dedicatedUsed = static_cast<qint64>(it->second);
                    if (const auto it = shared.find(g.luid); it != shared.end()) g.sharedUsed = static_cast<qint64>(it->second);
                }
            }
            primed = primed || collected;
        }
        s.gpus = gpus;
        if (!query) s.unavailable << QStringLiteral("disco e GPU: os contadores de desempenho do Windows não estão disponíveis");
        else if (!diskRead || !diskWrite) s.unavailable << QStringLiteral("disco: contador de leitura/gravação indisponível neste Windows");
        if (!adapterProblem.isEmpty()) s.unavailable << QStringLiteral("GPU: %1").arg(adapterProblem);
        else if (query && !gpuEngine)
            s.unavailable << QStringLiteral("GPU: este Windows não fornece o uso por mecanismo (requer Windows 10 1709 ou mais novo)");

        // Processes.
        const qint64 selfPid = static_cast<qint64>(GetCurrentProcessId());
        QList<ProcessUsage> all;
        QHash<qint64, Proc> next;
        const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(pe);
            for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
                if (pe.th32ProcessID == 0) continue;   // the idle "process" is the free CPU itself
                ++s.processes;
                ProcessUsage p;
                p.pid = static_cast<qint64>(pe.th32ProcessID);
                p.name = QString::fromWCharArray(pe.szExeFile);
                const HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (!h) {
                    ++s.unmeasured;   // protected processes: not even their times can be read
                    continue;
                }
                FILETIME created{}, exited{}, k{}, u{};
                if (GetProcessTimes(h, &created, &exited, &k, &u)) {
                    const Proc current{ft(k) + ft(u), ft(created)};
                    next.insert(p.pid, current);
                    const auto prev = procs.constFind(p.pid);
                    if (prev != procs.cend() && prev->created == current.created && elapsedMs > 0 && current.cpu >= prev->cpu)
                        p.cpuPercent = clampPercent(double(current.cpu - prev->cpu) /
                                                    (double(elapsedMs) * 10000.0 * s.logicalCpus) * 100.0);
                }
                PROCESS_MEMORY_COUNTERS pmc{};
                pmc.cb = sizeof(pmc);
                if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) p.memoryBytes = static_cast<qint64>(pmc.WorkingSetSize);
                CloseHandle(h);
                p.gpuPercent = processGpu.value(p.pid, query && gpuEngine && primed ? 0.0 : -1.0);
                if (p.pid == selfPid) s.self = p;
                all << p;
            }
            CloseHandle(snap);
        } else {
            s.unavailable << QStringLiteral("processos: a lista de processos do Windows não pôde ser lida");
        }
        procs = next;
        s.topCpu = top(all, topCount, &ProcessUsage::cpuPercent);
        s.topGpu = top(all, topCount, &ProcessUsage::gpuPercent);
        s.topMemory = topMemory(all, topCount);
        return s;
    }
};

#elif defined(__linux__)
// ============================================================================== Linux (development, CI)
namespace {

QByteArray readSmall(const QString& path) {
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.read(1 << 20) : QByteArray();
}

}  // namespace

MemoryStatus memoryStatus() {
    MemoryStatus m;
    for (const QByteArray& line : readSmall(QStringLiteral("/proc/meminfo")).split('\n')) {
        const QList<QByteArray> f = line.simplified().split(' ');
        if (f.size() < 2) continue;
        if (f[0] == "MemTotal:") m.total = f[1].toLongLong() * 1024;
        if (f[0] == "MemAvailable:") m.available = f[1].toLongLong() * 1024;
    }
    return m;
}

struct Sampler::Impl {
    struct Proc {
        quint64 ticks = 0, start = 0;
    };

    int topCount;
    QElapsedTimer clock;
    qint64 lastMs = -1;
    quint64 lastBusy = 0, lastTotal = 0;
    bool haveCpu = false;
    quint64 lastRead = 0, lastWrite = 0;
    bool haveDisk = false;
    QHash<qint64, Proc> procs;
    const double ticksPerSecond = static_cast<double>(sysconf(_SC_CLK_TCK));
    const qint64 pageSize = static_cast<qint64>(sysconf(_SC_PAGESIZE));

    explicit Impl(int n) : topCount(n) { clock.start(); }

    // Sectors read and written by physical block devices (not partitions, loop or RAM disks).
    bool diskSectors(quint64* read, quint64* written) const {
        bool any = false;
        *read = *written = 0;
        for (const QString& dev : QDir(QStringLiteral("/sys/block")).entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
            if (!QFileInfo::exists(QStringLiteral("/sys/block/%1/device").arg(dev))) continue;
            const QList<QByteArray> f = readSmall(QStringLiteral("/sys/block/%1/stat").arg(dev)).simplified().split(' ');
            if (f.size() < 7) continue;
            *read += f[2].toULongLong();
            *written += f[6].toULongLong();
            any = true;
        }
        return any;
    }

    Sample sample() {
        Sample s;
        s.atMs = QDateTime::currentMSecsSinceEpoch();
        s.logicalCpus = std::max(1, QThread::idealThreadCount());
        const qint64 now = clock.elapsed();
        const qint64 elapsedMs = lastMs < 0 ? -1 : now - lastMs;
        lastMs = now;

        const QList<QByteArray> cpu = readSmall(QStringLiteral("/proc/stat")).split('\n').value(0).simplified().split(' ');
        if (cpu.size() >= 9 && cpu[0] == "cpu") {
            quint64 total = 0;
            for (int i = 1; i <= 8; ++i) total += cpu[i].toULongLong();   // guest time is already inside user time
            const quint64 idle = cpu[4].toULongLong() + cpu[5].toULongLong();
            const quint64 busy = total - std::min(idle, total);
            if (haveCpu && total > lastTotal) s.cpuPercent = clampPercent(100.0 * double(busy - std::min(busy, lastBusy)) / double(total - lastTotal));
            lastBusy = busy;
            lastTotal = total;
            haveCpu = true;
        }
        const MemoryStatus mem = memoryStatus();
        s.memTotal = mem.total;
        s.memAvailable = mem.available;
        quint64 read = 0, written = 0;
        if (diskSectors(&read, &written)) {
            if (haveDisk && elapsedMs > 0) {
                s.diskReadBps = double(read - std::min(read, lastRead)) * 512.0 * 1000.0 / double(elapsedMs);
                s.diskWriteBps = double(written - std::min(written, lastWrite)) * 512.0 * 1000.0 / double(elapsedMs);
            }
            lastRead = read;
            lastWrite = written;
            haveDisk = true;
        } else {
            s.unavailable << QStringLiteral("disco: estatísticas de disco indisponíveis neste sistema");
        }
        s.unavailable << QStringLiteral("GPU: uso da placa de vídeo e da memória de vídeo medidos só no Windows");

        const qint64 selfPid = QCoreApplication::applicationPid();
        QList<ProcessUsage> all;
        QHash<qint64, Proc> next;
        for (const QString& entry : QDir(QStringLiteral("/proc")).entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
            bool numeric = false;
            const qint64 pid = entry.toLongLong(&numeric);
            if (!numeric) continue;
            ++s.processes;
            const QByteArray stat = readSmall(QStringLiteral("/proc/%1/stat").arg(pid));
            const int open = stat.indexOf('('), close = stat.lastIndexOf(')');
            if (open < 0 || close < open) {
                ++s.unmeasured;
                continue;
            }
            const QList<QByteArray> f = stat.mid(close + 2).simplified().split(' ');   // f[0] = field 3 (state)
            if (f.size() < 22) {
                ++s.unmeasured;
                continue;
            }
            ProcessUsage p;
            p.pid = pid;
            p.name = QString::fromUtf8(stat.mid(open + 1, close - open - 1));
            const Proc nowProc{f[11].toULongLong() + f[12].toULongLong(), f[19].toULongLong()};
            next.insert(pid, nowProc);
            const auto prev = procs.constFind(pid);
            if (prev != procs.cend() && prev->start == nowProc.start && elapsedMs > 0 && nowProc.ticks >= prev->ticks)
                p.cpuPercent = clampPercent(double(nowProc.ticks - prev->ticks) / ticksPerSecond /
                                            (double(elapsedMs) / 1000.0 * s.logicalCpus) * 100.0);
            p.memoryBytes = f[21].toLongLong() * pageSize;
            if (pid == selfPid) s.self = p;
            all << p;
        }
        procs = next;
        s.topCpu = top(all, topCount, &ProcessUsage::cpuPercent);
        s.topMemory = topMemory(all, topCount);
        return s;
    }
};

#else
MemoryStatus memoryStatus() { return {}; }

struct Sampler::Impl {
    explicit Impl(int) {}
    Sample sample() {
        Sample s;
        s.atMs = QDateTime::currentMSecsSinceEpoch();
        s.unavailable << QStringLiteral("monitor de desempenho não suportado nesta plataforma");
        return s;
    }
};
#endif

Sampler::Sampler(int topCount) : impl_(std::make_unique<Impl>(std::clamp(topCount, 1, 50))) {}
Sampler::~Sampler() = default;
Sample Sampler::sample() { return impl_->sample(); }

}  // namespace gk::perf
