// Tests of the Performance Monitor (M12) on the real machine: Windows counters/DXGI in the Windows CI, /proc on
// Linux. Driven by pytest (tests/integration/test_cpp_perf.py). Nothing is changed on the system.
#include "gk/perf/sampler.hpp"

#include <QCoreApplication>
#include <QJsonArray>
#include <QtTest>

#include <atomic>
#include <chrono>
#include <thread>

using namespace gk::perf;

class TestPerf : public QObject {
    Q_OBJECT

private slots:
    void measuresTheMachineAndItsBusiestProcesses() {
        Sampler sampler(5);
        const Sample first = sampler.sample();
        QVERIFY(first.logicalCpus >= 1);
        QCOMPARE(first.cpuPercent, -1.0);   // rates need two samples
        QVERIFY(first.memTotal > 0);
        QVERIFY(first.memAvailable > 0 && first.memAvailable <= first.memTotal);
        QVERIFY(first.processes > 1);
        QCOMPARE(first.self.pid, QCoreApplication::applicationPid());
        QVERIFY(first.self.memoryBytes > 0);
        QVERIFY(first.topMemory.size() <= 5 && !first.topMemory.isEmpty());

        // Keep one core busy: this process must show it.
        std::atomic<bool> stop{false};
        std::thread busy([&stop] {
            volatile double x = 0;
            while (!stop.load()) x = x + 1.0;
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        const Sample second = sampler.sample();
        stop = true;
        busy.join();

        QVERIFY(second.cpuPercent >= 0 && second.cpuPercent <= 100);
        QVERIFY2(second.self.cpuPercent >= 40.0 / second.logicalCpus,
                 qPrintable(QStringLiteral("CPU deste processo: %1% de %2 processadores").arg(second.self.cpuPercent).arg(second.logicalCpus)));
        QVERIFY(second.cpuPercent + 0.5 >= second.self.cpuPercent * 0.5);   // the machine is at least partly busy
        for (int i = 1; i < second.topCpu.size(); ++i) QVERIFY(second.topCpu[i - 1].cpuPercent >= second.topCpu[i].cpuPercent);
        for (int i = 1; i < second.topMemory.size(); ++i) QVERIFY(second.topMemory[i - 1].memoryBytes >= second.topMemory[i].memoryBytes);
        QVERIFY(!second.topCpu.isEmpty());

        // Disk and GPU: a value, or the reason it is not available here.
        auto explained = [&](const QString& what) {
            for (const QString& u : second.unavailable)
                if (u.startsWith(what)) return true;
            return false;
        };
        QVERIFY((second.diskReadBps >= 0 && second.diskWriteBps >= 0) || explained(QStringLiteral("disco")));
#ifdef _WIN32
        if (second.gpus.isEmpty()) {
            QVERIFY(explained(QStringLiteral("GPU")));
        } else {
            for (const GpuAdapter& g : second.gpus) {
                QVERIFY(!g.name.isEmpty());
                QVERIFY(g.luid.startsWith(QStringLiteral("luid_0x")));
                QVERIFY(g.utilization >= 0 && g.utilization <= 100);
            }
        }
#else
        QVERIFY(second.gpus.isEmpty());
        QVERIFY(explained(QStringLiteral("GPU")));
#endif
        const QJsonObject j = toJson(second);
        for (const char* key : {"cpu_percent", "memory_total", "memory_available", "disk_read_bps", "gpus", "top_cpu",
                                "top_memory", "top_gpu", "self", "unavailable", "logical_cpus"})
            QVERIFY2(j.contains(QLatin1String(key)), key);
        QCOMPARE(j.value("self").toObject().value("pid").toInteger(), QCoreApplication::applicationPid());

        const MemoryStatus m = memoryStatus();
        QVERIFY(m.total == second.memTotal);
    }
};

QTEST_GUILESS_MAIN(TestPerf)
#include "tst_perf.moc"
