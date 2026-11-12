#include "gk/scan/scanner.hpp"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QProcess>
#include <QStandardPaths>
#include <QTimer>

#include <chrono>

#include "gk/authenticode.hpp"
#include "gk/error.hpp"
#include "gk/hash.hpp"
#include "gk/ipc/helper_client.hpp"
#include "gk/risk.hpp"
#include "gk/serialize.hpp"
#include "gk/version.hpp"

namespace gk::scan {

namespace {

using nlohmann::json;

double now_seconds() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

QJsonObject to_qt(const json& j) {
    return QJsonDocument::fromJson(QByteArray::fromStdString(j.dump(-1, ' ', false, json::error_handler_t::replace))).object();
}

json from_qt(const QJsonObject& o) {
    return json::parse(QJsonDocument(o).toJson(QJsonDocument::Compact).toStdString());
}

std::string utf8(const QString& s) { return s.toStdString(); }

bool has_files(const QString& dir, const QStringList& filters) {
    return !QDir(dir).entryList(filters, QDir::Files).isEmpty();
}

QString exe(const QString& base) {
#ifdef Q_OS_WIN
    return base + QStringLiteral(".exe");
#else
    return base;
#endif
}

}  // namespace

// ------------------------------------------------------------------------------------- Config

Config Config::defaults(const QString& appDir, const QString& dataDir) {
    Config c;
    c.dataDir = dataDir;
    // Installed layout keeps resources next to the executable; a build tree finds them in a parent folder.
    QDir probe(appDir);
    for (int i = 0; i < 6; ++i) {
        if (QFileInfo::exists(probe.filePath(QStringLiteral("signatures/internal/indicators.yar")))) {
            c.resourceDir = probe.absolutePath();
            break;
        }
        if (!probe.cdUp()) break;
    }
    if (c.resourceDir.isEmpty()) c.resourceDir = appDir;
    for (const QString& candidate : {QDir(appDir).filePath(exe(QStringLiteral("gk-scanworker"))),
                                     QDir(appDir).filePath(QStringLiteral("../worker/") + exe(QStringLiteral("gk-scanworker")))}) {
        if (QFileInfo(candidate).isExecutable()) {
            c.workerProgram = QFileInfo(candidate).absoluteFilePath();
            break;
        }
    }
    const QString bundled = QDir(c.resourceDir).filePath(QStringLiteral("third_party/clamav/") + exe(QStringLiteral("clamscan")));
    c.clamscan = QFileInfo(bundled).isExecutable() ? bundled : QStandardPaths::findExecutable(QStringLiteral("clamscan"));
    return c;
}

QStringList Config::detectionRuleDirs() const {
    return {QDir(resourceDir).filePath(QStringLiteral("signatures/yara")),
            QDir(dataDir).filePath(QStringLiteral("signatures/active/yara"))};
}
QString Config::indicatorFile() const { return QDir(resourceDir).filePath(QStringLiteral("signatures/internal/indicators.yar")); }
QStringList Config::iocDirs() const {
    return {QDir(resourceDir).filePath(QStringLiteral("signatures/ioc")),
            QDir(dataDir).filePath(QStringLiteral("signatures/active/ioc"))};
}
QStringList Config::clamavDatabaseDirs() const {
    QStringList dirs;
    const QStringList filters{QStringLiteral("*.cvd"), QStringLiteral("*.cld"), QStringLiteral("*.cud"),
                              QStringLiteral("*.hdb"), QStringLiteral("*.hsb"), QStringLiteral("*.ndb"),
                              QStringLiteral("*.ldb"), QStringLiteral("*.mdb"), QStringLiteral("*.msb")};
    for (const QString& d : {QDir(resourceDir).filePath(QStringLiteral("signatures/clamav")),
                             QDir(dataDir).filePath(QStringLiteral("signatures/active/clamav"))}) {
        if (has_files(d, filters)) dirs << d;
    }
    return dirs;
}
QString Config::componentsFile() const {
    const QString active = QDir(dataDir).filePath(QStringLiteral("signatures/active/data/game_components.json"));
    return QFileInfo::exists(active) ? active : QDir(resourceDir).filePath(QStringLiteral("signatures/data/game_components.json"));
}
QString Config::catalogFile() const { return QDir(resourceDir).filePath(QStringLiteral("contracts/threat_catalog.json")); }
QString Config::databaseFile() const { return QDir(dataDir).filePath(QStringLiteral("gamekernel.db")); }

// ------------------------------------------------------------------------------------- Scanner

Scanner::Scanner(Config config, QObject* parent) : QObject(parent), config_(std::move(config)) {
    qRegisterMetaType<gk::scan::Progress>();
}

Scanner::~Scanner() {
    for (auto& s : slots_) {
        if (s.client) s.client->stop(2000);
    }
}

std::string Scanner::fingerprint() const {
    // Cached verdicts are reused only when everything that produces them is identical.
    Sha256 h;
    auto add = [&](const std::string& s) { h.update(ByteView(s)); h.update(ByteView(std::string_view("\x1f", 1))); };
    add(kVersion);
    // Analysis revisions that change results without a version bump (Authenticode evidence; trust only on Windows).
    add(gk::authenticode::trust_supported() ? "authenticode-1+trust" : "authenticode-1");
    add(request_.deep ? "deep" : "quick");
    add(QJsonDocument(config_.archiveLimits).toJson(QJsonDocument::Compact).toStdString());
    QStringList files;
    for (const QString& d : config_.detectionRuleDirs()) {
        for (const QFileInfo& fi : QDir(d).entryInfoList({QStringLiteral("*.yar"), QStringLiteral("*.yara")}, QDir::Files, QDir::Name)) {
            files << fi.absoluteFilePath();
        }
    }
    files << config_.indicatorFile();
    for (const QString& f : files) {
        QFile file(f);
        if (file.open(QIODevice::ReadOnly)) {
            add(utf8(QFileInfo(f).fileName()));
            const QByteArray data = file.readAll();
            h.update(ByteView(reinterpret_cast<const std::uint8_t*>(data.constData()), static_cast<std::size_t>(data.size())));
        }
    }
    return to_hex(h.finish()).substr(0, 32);
}

FileResult Scanner::skeleton(const Candidate& c) const {
    FileResult r;
    r.path = c.path_utf8;
    const QFileInfo fi(QString::fromStdString(c.path_utf8));
    r.name = utf8(fi.fileName());
    r.directory = utf8(fi.absolutePath());
    r.extension = extension_of(c.path);
    r.size = c.size;
    r.file_type = c.type.kind.empty() ? "unknown" : c.type.kind;
    r.features.file_type = r.file_type;
    r.analyzed_at = now_seconds();
    return r;
}

qint64 Scanner::start(const Request& request) {
    if (running_) return 0;
    request_ = request;
    token_ = std::make_shared<CancelToken>();
    cancelled_ = false;
    results_.clear();
    candidates_.clear();
    queue_.clear();
    next_ = 0;
    inFlight_ = 0;
    pathCache_.clear();
    verdicts_.clear();
    warnings_.clear();
    limitations_.clear();
    progress_ = Progress{};
    startedAt_ = now_seconds();

    try {
        db_ = db::Database::open(std::filesystem::path(utf8(config_.databaseFile())));
        if (db_->recovered_from()) {
            warnings_.push_back("O banco de dados estava corrompido e foi recriado; cópia guardada em " +
                                db_->recovered_from()->string());
        }
    } catch (const std::exception& e) {
        emit finished(QJsonObject{{QStringLiteral("status"), QStringLiteral("failed")},
                                  {QStringLiteral("error"), QString::fromStdString(e.what())}});
        return 0;
    }
    if (config_.workerProgram.isEmpty() || !QFileInfo(config_.workerProgram).isExecutable()) {
        emit finished(QJsonObject{{QStringLiteral("status"), QStringLiteral("failed")},
                                  {QStringLiteral("error"), QStringLiteral("gk-scanworker não encontrado")}});
        return 0;
    }
    fingerprint_ = fingerprint();
    json targets = json::array();
    for (const QString& t : request.targets) targets.push_back(utf8(t));
    json options{{"mode", request.deep ? "deep" : "quick"}, {"use_cache", request.useCache}, {"workers", config_.workers}};
    scanId_ = db_->create_scan(request.deep ? "deep" : "quick", targets, options, fingerprint_, utf8(request.origin),
                               utf8(request.label));
    running_ = true;
    progress_.scanId = scanId_;
    progress_.phase = QStringLiteral("enumerating");
    emitProgress(true);

    std::vector<std::filesystem::path> paths;
    for (const QString& t : request.targets) paths.emplace_back(std::u8string(reinterpret_cast<const char8_t*>(t.toStdString().c_str())));
    EnumOptions eo = config_.enumeration;
    eo.deep = request.deep;
    EnumResult er = enumerate(paths, eo, token_.get(), [this](std::size_t n) {
        progress_.filesTotal = n;
        emitProgress();
    });
    for (const auto& e : er.errors) warnings_.push_back("Não foi possível ler: " + e);
    candidates_ = std::move(er.files);
    progress_.filesTotal = candidates_.size();

    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        const Candidate& c = candidates_[i];
        if (!c.selected) {
            FileResult r = skeleton(c);
            r.status = AnalysisStatus::Skipped;
            r.status_reasons.push_back(c.skip_reason);
            if (c.type.disguised) r.status = AnalysisStatus::Partial;
            results_.push_back(std::move(r));
            ++progress_.skipped;
            ++progress_.filesDone;
            continue;
        }
        if (request.useCache) {
            if (auto pc = db_->path_cache(c.path_utf8); pc && pc->size == c.size && pc->mtime_ns == c.mtime_ns) {
                if (auto cached = db_->verdict(pc->sha256, fingerprint_)) {
                    try {
                        FileResult top = file_result_from_json((*cached)["file"]);
                        top.from_cache = true;
                        top.path = c.path_utf8;
                        results_.push_back(std::move(top));
                        for (const auto& m : cached->value("members", json::array())) {
                            FileResult member = file_result_from_json(m);
                            member.from_cache = true;
                            results_.push_back(std::move(member));
                            ++progress_.members;
                        }
                        ++progress_.filesDone;
                        progress_.bytesDone += c.size;
                        continue;
                    } catch (const std::exception&) {
                        // stale or corrupt cache entry: analyse again
                    }
                }
            }
        }
        queue_.push_back(i);
    }

    progress_.phase = QStringLiteral("analyzing");
    const std::size_t workers = std::max<std::size_t>(1, std::min<std::size_t>(static_cast<std::size_t>(config_.workers), queue_.size()));
    if (!queue_.empty()) {
        ipc::HelperConfig hc;
        hc.program = config_.workerProgram;
        for (const QString& d : config_.detectionRuleDirs()) hc.arguments << QStringLiteral("--rules") << d;
        hc.arguments << QStringLiteral("--indicators") << config_.indicatorFile();
        hc.workingDirectory = QFileInfo(config_.workerProgram).absolutePath();
        hc.environment = ipc::sanitizedEnvironment(config_.dataDir);
        hc.memoryLimitBytes = config_.workerMemoryLimit;
        hc.helloTimeoutMs = 60000;
        slots_.resize(workers);
        for (std::size_t s = 0; s < workers; ++s) {
            auto* client = new ipc::HelperClient(hc, this);
            slots_[s].client = client;
            connect(client, &ipc::HelperClient::callSucceeded, this,
                    [this, s](qint64 id, const QJsonValue& v) { onCallSucceeded(s, id, v); });
            connect(client, &ipc::HelperClient::callFailed, this,
                    [this, s](qint64 id, const ipc::CallError& e) { onCallFailed(s, id, e.reason, e.message); });
            connect(client, &ipc::HelperClient::eventReceived, this,
                    [this, s](qint64 id, const QString& name, const QJsonObject& data) { onEvent(s, id, name, data); });
            connect(client, &ipc::HelperClient::ready, this, [this](const QJsonObject& hello) {
                const QJsonObject rules = hello.value(QStringLiteral("rules")).toObject();
                if (rules.value(QStringLiteral("indicators")).toInt() == 0) {
                    warnings_.push_back("O processo de análise não carregou os indicadores de capacidade.");
                }
            });
        }
    }
    emitProgress(true);
    QTimer::singleShot(0, this, [this] { queue_.empty() ? finishAnalysis() : dispatch(); });
    return scanId_;
}

void Scanner::pause() {
    if (token_) token_->pause();
    progress_.paused = true;
    if (db_ && running_) db_->update_scan(scanId_, {}, "paused");
    emitProgress(true);
}

void Scanner::resume() {
    if (token_) token_->resume();
    progress_.paused = false;
    emitProgress(true);
    QTimer::singleShot(0, this, [this] { dispatch(); });
}

void Scanner::cancel() {
    if (!running_) return;
    cancelled_ = true;
    if (token_) token_->cancel();
    QTimer::singleShot(0, this, [this] {
        for (auto& s : slots_) {
            if (s.job && s.client) s.client->cancel(s.callId);
        }
        if (inFlight_ == 0) finishAnalysis();
    });
}

void Scanner::dispatch() {
    if (!running_ || progress_.phase != QStringLiteral("analyzing")) return;
    if (cancelled_) {
        if (inFlight_ == 0) finishAnalysis();
        return;
    }
    if (token_->paused()) return;
    for (std::size_t s = 0; s < slots_.size(); ++s) {
        Slot& slot = slots_[s];
        if (slot.job || next_ >= queue_.size()) continue;
        const std::size_t idx = queue_[next_++];
        slot.job = Job{idx, 0};
        slot.members.clear();
        const Candidate& c = candidates_[idx];
        QJsonObject params{{QStringLiteral("path"), QString::fromStdString(c.path_utf8)},
                           {QStringLiteral("deep"), request_.deep},
                           {QStringLiteral("limits"), config_.archiveLimits}};
        const int timeout = config_.fileTimeoutMs + static_cast<int>(std::min<std::uint64_t>(c.size / (4u << 10), 600000));
        slot.callId = slot.client->call(QStringLiteral("analyze"), params, timeout);
        ++inFlight_;
        progress_.current = QString::fromStdString(c.path_utf8);
        emitProgress();
    }
    if (next_ >= queue_.size() && inFlight_ == 0) finishAnalysis();
}

void Scanner::onEvent(std::size_t s, qint64 id, const QString& name, const QJsonObject& data) {
    Slot& slot = slots_[s];
    if (id != slot.callId || name != QStringLiteral("member")) return;
    try {
        slot.members.push_back(file_result_from_json(from_qt(data)));
    } catch (const std::exception& e) {
        warnings_.push_back(std::string("membro com resultado inválido descartado: ") + e.what());
    }
}

void Scanner::onCallSucceeded(std::size_t s, qint64 id, const QJsonValue& value) {
    Slot& slot = slots_[s];
    if (!slot.job || id != slot.callId) return;
    std::vector<FileResult> results;
    try {
        results.push_back(file_result_from_json(from_qt(value.toObject().value(QStringLiteral("file")).toObject())));
    } catch (const std::exception& e) {
        onCallFailed(s, id, QStringLiteral("invalid_format"), QString::fromStdString(e.what()));
        return;
    }
    for (auto& m : slot.members) results.push_back(std::move(m));
    slot.members.clear();
    completeJob(s, std::move(results), true);
}

void Scanner::onCallFailed(std::size_t s, qint64 id, const QString& reason, const QString& message) {
    Slot& slot = slots_[s];
    if (!slot.job || id != slot.callId) return;
    FileResult r = skeleton(candidates_[slot.job->candidate]);
    if (reason == QStringLiteral("helper_crashed")) {
        r.status = AnalysisStatus::Error;
        r.status_reasons.push_back("o processo de análise isolado falhou ao ler este arquivo (possível arquivo "
                                   "malformado ou malicioso). O arquivo não foi executado.");
    } else if (reason == QStringLiteral("timeout")) {
        r.status = AnalysisStatus::Partial;
        r.status_reasons.push_back("tempo limite de análise excedido");
    } else if (reason == QStringLiteral("cancelled")) {
        r.status = AnalysisStatus::Skipped;
        r.status_reasons.push_back("análise cancelada");
    } else if (reason == QStringLiteral("helper_unavailable")) {
        r.status = AnalysisStatus::Error;
        r.status_reasons.push_back("o processo de análise isolado ficou indisponível após falhas repetidas; o arquivo "
                                   "não foi analisado nem executado (" + utf8(message) + ")");
    } else {
        r.status = AnalysisStatus::Error;
        r.status_reasons.push_back(utf8(message.isEmpty() ? reason : message));
    }
    if (r.status == AnalysisStatus::Error) ++progress_.errors;
    if (reason == QStringLiteral("helper_unavailable")) {
        warnings_.push_back("O processo de análise não pôde ser iniciado: " + utf8(message));
        slot.client->resetFailures();
    }
    slot.members.clear();
    completeJob(s, {std::move(r)}, false);
}

void Scanner::completeJob(std::size_t s, std::vector<FileResult> results, bool fromWorker) {
    Slot& slot = slots_[s];
    const Candidate& c = candidates_[slot.job->candidate];
    slot.job.reset();
    --inFlight_;
    if (!results.empty()) {
        FileResult& top = results.front();
        top.path = c.path_utf8;
        if (fromWorker && top.sha256 && (top.status == AnalysisStatus::Complete || top.status == AnalysisStatus::Partial)) {
            pathCache_.emplace_back(c.path_utf8, db::PathCacheEntry{c.size, c.mtime_ns, *top.sha256, top.md5.value_or("")});
            json payload{{"file", to_json(top)}, {"members", json::array()}};
            for (std::size_t i = 1; i < results.size(); ++i) payload["members"].push_back(to_json(results[i]));
            verdicts_.emplace_back(*top.sha256, fingerprint_, std::move(payload));
        }
        progress_.members += results.size() - 1;
        for (auto& r : results) results_.push_back(std::move(r));
    }
    ++progress_.filesDone;
    progress_.bytesDone += c.size;
    emitProgress();
    dispatch();
}

void Scanner::finishAnalysis() {
    if (progress_.phase != QStringLiteral("analyzing") && progress_.phase != QStringLiteral("enumerating")) return;
    progress_.phase = QStringLiteral("signatures");
    emitProgress(true);
    runClamav();
    finalize();
}

void Scanner::runClamav() {
    if (cancelled_) return;
    if (config_.clamscan.isEmpty()) {
        limitations_.push_back("ClamAV indisponível nesta instalação: arquivos não verificados por assinaturas do ClamAV.");
        return;
    }
    const QStringList dbs = config_.clamavDatabaseDirs();
    if (dbs.isEmpty()) {
        limitations_.push_back("Nenhum banco de assinaturas do ClamAV instalado: importe um pacote de atualização offline.");
        return;
    }
    // Database identity: names, sizes and modification times of every database file.
    Sha256 h;
    for (const QString& d : dbs) {
        for (const QFileInfo& fi : QDir(d).entryInfoList(QDir::Files, QDir::Name)) {
            const std::string key = utf8(fi.fileName()) + ":" + std::to_string(fi.size()) + ":" +
                                    std::to_string(fi.lastModified().toSecsSinceEpoch());
            h.update(ByteView(key));
        }
    }
    const std::string clam_fp = "clamav|" + to_hex(h.finish()).substr(0, 24);

    std::map<std::string, std::size_t> by_path;      // top-level path -> result index
    std::vector<std::string> pending;
    for (std::size_t i = 0; i < results_.size(); ++i) {
        const FileResult& r = results_[i];
        if (r.container || r.status == AnalysisStatus::Skipped || r.status == AnalysisStatus::Error || !r.sha256) continue;
        if (auto cached = db_->verdict(*r.sha256, clam_fp)) {
            if (cached->contains("signature") && (*cached)["signature"].is_string()) {
                results_[i].evidences.push_back(clamav_evidence((*cached)["signature"].get<std::string>(),
                                                                r.file_type == "zip" || r.file_type == "7z" || r.file_type == "rar"));
            }
            continue;
        }
        by_path[r.path] = i;
        pending.push_back(r.path);
    }
    QDir().mkpath(QDir(config_.dataDir).filePath(QStringLiteral("temp")));
    std::vector<std::tuple<std::string, std::string, json>> clam_cache;
    for (std::size_t start = 0; start < pending.size() && !cancelled_; start += static_cast<std::size_t>(config_.clamavBatch)) {
        const std::size_t end = std::min(pending.size(), start + static_cast<std::size_t>(config_.clamavBatch));
        const QString list = QDir(config_.dataDir).filePath(QStringLiteral("temp/clamav-list-%1.txt").arg(scanId_));
        {
            QFile f(list);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                warnings_.push_back("Não foi possível preparar a lista para o ClamAV.");
                return;
            }
            for (std::size_t i = start; i < end; ++i) f.write(QByteArray::fromStdString(pending[i] + "\n"));
        }
        QStringList args{QStringLiteral("--no-summary"), QStringLiteral("--stdout"), QStringLiteral("--infected"),
                         QStringLiteral("--detect-pua=yes"), QStringLiteral("--heuristic-alerts=yes"),
                         QStringLiteral("--alert-exceeds-max=no"), QStringLiteral("--max-filesize=400M"),
                         QStringLiteral("--max-scansize=800M"), QStringLiteral("--max-recursion=8"),
                         QStringLiteral("--file-list=") + list};
        for (const QString& d : dbs) args << QStringLiteral("--database=") + d;
        QProcess proc;
        proc.setWorkingDirectory(QFileInfo(config_.clamscan).absolutePath());
        proc.setProcessEnvironment(ipc::sanitizedEnvironment(config_.dataDir));
        proc.start(config_.clamscan, args);
        if (!proc.waitForStarted(30000)) {
            warnings_.push_back("O ClamAV não pôde ser iniciado: " + utf8(proc.errorString()));
            return;
        }
        progress_.current = QStringLiteral("ClamAV: lote %1–%2 de %3").arg(start + 1).arg(end).arg(pending.size());
        emitProgress(true);
        while (!proc.waitForFinished(250)) {
            QCoreApplication::processEvents();
            if (cancelled_) {
                proc.kill();
                proc.waitForFinished(5000);
                return;
            }
        }
        const std::string out = proc.readAllStandardOutput().toStdString();
        if (proc.exitCode() == 2) warnings_.push_back("O ClamAV relatou erros em alguns arquivos: " + proc.readAllStandardError().left(300).toStdString());
        const auto hits = parse_clamscan(out);
        for (std::size_t i = start; i < end; ++i) {
            FileResult& r = results_[by_path[pending[i]]];
            auto it = hits.find(pending[i]);
            if (std::find(r.engines.begin(), r.engines.end(), "clamav") == r.engines.end()) r.engines.emplace_back("clamav");
            if (it != hits.end()) {
                r.evidences.push_back(clamav_evidence(it->second, r.file_type == "zip" || r.file_type == "7z" || r.file_type == "rar"));
            }
            clam_cache.emplace_back(*r.sha256, clam_fp, it != hits.end() ? json{{"signature", it->second}} : json{{"signature", nullptr}});
        }
    }
    QFile::remove(QDir(config_.dataDir).filePath(QStringLiteral("temp/clamav-list-%1.txt").arg(scanId_)));
    if (!clam_cache.empty()) db_->put_verdicts(clam_cache);
}

void Scanner::finalize() {
    progress_.phase = QStringLiteral("context");
    emitProgress(true);
    // Local reputation (IOC files + the user's own trusted/blocked marks).
    std::vector<std::string> ioc_errors;
    std::vector<std::filesystem::path> ioc_dirs;
    for (const QString& d : config_.iocDirs()) ioc_dirs.emplace_back(utf8(d));
    const IocDb iocs = IocDb::load(ioc_dirs, &ioc_errors);
    for (const auto& e : ioc_errors) warnings_.push_back("Base local de IOCs: " + e);
    for (auto& r : results_) {
        if (!r.sha256) continue;
        if (const IocEntry* e = iocs.find(*r.sha256)) {
            if (auto ev = reputation_evidence(e->verdict, e->name, e->category, e->severity, "base local de IOCs " + iocs.version())) {
                r.evidences.push_back(std::move(*ev));
            }
        }
        if (auto rep = db_->reputation(*r.sha256)) {
            if (auto ev = reputation_evidence(rep->verdict, rep->name, std::string(category::kGenericMalware), "HIGH",
                                              "marcação do usuário")) {
                r.evidences.push_back(std::move(*ev));
            }
        }
    }
    try {
        const auto components = risk::ComponentDb::load(std::filesystem::path(utf8(config_.componentsFile())));
        const auto catalog = risk::Catalog::load(std::filesystem::path(utf8(config_.catalogFile())));
        risk::assess_all(results_, components, catalog);
    } catch (const std::exception& e) {
        warnings_.push_back(std::string("Motor de risco: ") + e.what());
    }

    progress_.phase = QStringLiteral("saving");
    emitProgress(true);
    db::ScanCounters counters;
    json by_class = json::object();
    json by_risk = json::object();
    for (const auto& r : results_) {
        by_class[std::string(value_of(r.classification))] = by_class.value(std::string(value_of(r.classification)), 0) + 1;
        by_risk[std::string(name_of(r.risk))] = by_risk.value(std::string(name_of(r.risk)), 0) + 1;
        counters.max_risk = std::max(counters.max_risk, r.risk);
        if (r.classification == Classification::Malware) ++counters.threats;
        if (r.classification == Classification::Suspicious) ++counters.suspicious;
        if (r.classification == Classification::Pua) ++counters.pua;
        if (r.container) {
            ++counters.members_analyzed;
            continue;
        }
        if (r.status == AnalysisStatus::Skipped) ++counters.files_skipped;
        else if (r.status == AnalysisStatus::Error) ++counters.files_errors;
        else ++counters.files_analyzed;
        counters.bytes_scanned += r.status == AnalysisStatus::Skipped ? 0 : r.size;
    }
    counters.files_found = candidates_.size();
    progress_.threats = counters.threats;
    progress_.suspicious = counters.suspicious;
    progress_.pua = counters.pua;

    limitations_.push_back("Análise estática: os arquivos não são executados; comportamentos que só aparecem em "
                           "execução exigem a análise na sandbox isolada.");
    if (gk::authenticode::trust_supported()) {
        limitations_.push_back("Assinaturas digitais verificadas sem acesso à rede: revogações de certificados só são "
                               "detectadas se a informação já estiver no computador; dentro de compactados, só a "
                               "integridade da assinatura é conferida.");
    } else {
        limitations_.push_back("A cadeia de confiança das assinaturas digitais só é verificada no Windows; nesta "
                               "plataforma apenas a integridade (resumo assinado × conteúdo) é conferida.");
    }
    if (!request_.deep) {
        limitations_.push_back("Modo rápido: arquivos de dados verificados só pelo cabeçalho e conteúdo de compactados não expandido.");
    }
    const std::string status = cancelled_ ? "cancelled" : "completed";
    json summary{{"scan_id", scanId_},
                 {"status", status},
                 {"mode", request_.deep ? "deep" : "quick"},
                 {"targets", json::array()},
                 {"started_at", startedAt_},
                 {"finished_at", now_seconds()},
                 {"files_found", counters.files_found},
                 {"files_analyzed", counters.files_analyzed},
                 {"files_skipped", counters.files_skipped},
                 {"files_errors", counters.files_errors},
                 {"members_analyzed", counters.members_analyzed},
                 {"bytes_scanned", counters.bytes_scanned},
                 {"counts_by_classification", by_class},
                 {"counts_by_risk", by_risk},
                 {"max_risk", name_of(counters.max_risk)},
                 {"engines",
                  json::array({json{{"key", "worker"}, {"name", "Análise estática isolada (PE, YARA, compactados, scripts)"},
                                    {"available", true}, {"enabled", true}, {"version", kVersion}, {"detail", ""}},
                               json{{"key", "clamav"}, {"name", "ClamAV"}, {"available", !config_.clamscan.isEmpty()},
                                    {"enabled", true}, {"version", ""}, {"detail", utf8(config_.clamscan)}},
                               json{{"key", "reputation"}, {"name", "Reputação local"}, {"available", true},
                                    {"enabled", true}, {"version", iocs.version()},
                                    {"detail", std::to_string(iocs.size()) + " hashes"}}})},
                 {"limitations", limitations_},
                 {"warnings", warnings_},
                 {"error", nullptr},
                 {"fingerprint", fingerprint_}};
    for (const QString& t : request_.targets) summary["targets"].push_back(utf8(t));
    try {
        db_->add_file_results(scanId_, results_);
        if (!pathCache_.empty()) db_->put_path_cache(pathCache_);
        if (!verdicts_.empty()) db_->put_verdicts(verdicts_);
        db_->finish_scan(scanId_, status, counters, summary, "");
    } catch (const std::exception& e) {
        summary["status"] = "failed";
        summary["error"] = e.what();
    }
    progress_.phase = QStringLiteral("done");
    progress_.current.clear();
    emitProgress(true);
    for (const auto& r : results_) emit fileResult(to_qt(to_json(r)));
    for (auto& s : slots_) {
        if (s.client) {
            s.client->stop(2000);
            s.client->deleteLater();
        }
    }
    slots_.clear();
    running_ = false;
    emit finished(to_qt(summary));
}

void Scanner::emitProgress(bool force) {
    static QElapsedTimer timer;
    if (!timer.isValid()) timer.start();
    const qint64 now = timer.elapsed();
    if (!force && now - lastProgressMs_ < 100) return;
    lastProgressMs_ = now;
    progress_.paused = token_ && token_->paused();
    emit progress(progress_);
}

}  // namespace gk::scan
