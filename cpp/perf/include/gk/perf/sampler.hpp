// Performance Monitor (M12): what the computer is spending right now, measured by the operating system itself.
//
// Windows (the product): CPU from GetSystemTimes; memory from GlobalMemoryStatusEx; disk throughput and GPU
// engine utilisation / dedicated video memory from Performance Data Helper counters added by their English
// names (independent of the Windows language); adapter names and total video memory from DXGI; processes from a
// Toolhelp snapshot with GetProcessTimes / GetProcessMemoryInfo. Linux (development and CI): /proc and
// /sys/block; GPU metrics are not available there and are reported as such.
//
// Read-only: nothing is changed, no process is touched beyond querying it. Rates (CPU, disk, per-process CPU)
// come from the difference between two consecutive samples, so the first sample has none (-1).
#pragma once

#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

#include <memory>

namespace gk::perf {

struct GpuAdapter {
    QString name;
    QString luid;                 // "luid_0x%08X_0x%08X" (matches the counter instances)
    double utilization = -1;      // percent of the busiest engine type, -1 = unknown
    qint64 dedicatedTotal = 0;    // bytes (DXGI)
    qint64 dedicatedUsed = -1;    // bytes, all processes (-1 = unknown)
    qint64 sharedUsed = -1;
};

struct ProcessUsage {
    qint64 pid = 0;
    QString name;
    double cpuPercent = -1;       // of the whole machine (all logical processors)
    double gpuPercent = -1;       // busiest engine type used by the process (Windows)
    qint64 memoryBytes = 0;       // working set
};

struct Sample {
    qint64 atMs = 0;
    int logicalCpus = 0;
    double cpuPercent = -1;
    qint64 memTotal = 0, memAvailable = 0;
    double diskReadBps = -1, diskWriteBps = -1;
    QList<GpuAdapter> gpus;
    QList<ProcessUsage> topCpu, topMemory, topGpu;   // up to `topCount` each
    ProcessUsage self;                               // this program
    int processes = 0;                               // processes seen
    int unmeasured = 0;                              // processes that could not be queried (protected)
    QStringList unavailable;                         // metrics this system does not provide, and why
};

QJsonObject toJson(const Sample& sample);

// Physical memory right now (bytes; 0 when unknown). Also used by the optimizer's diagnostics.
struct MemoryStatus {
    qint64 total = 0, available = 0;
};
MemoryStatus memoryStatus();

class Sampler {
public:
    explicit Sampler(int topCount = 8);
    ~Sampler();
    Sampler(const Sampler&) = delete;
    Sampler& operator=(const Sampler&) = delete;
    Sample sample();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace gk::perf
