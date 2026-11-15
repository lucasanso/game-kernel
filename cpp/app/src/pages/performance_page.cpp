#include "performance_page.hpp"

#include "../ui_kit.hpp"

#include <QComboBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QLabel>
#include <QLocale>
#include <QPainter>
#include <QPainterPath>
#include <QTableWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <deque>

namespace gk::app {

// The last minute of one metric, drawn as a line (no chart library: a few points and a fill).
class Sparkline : public QWidget {
public:
    explicit Sparkline(QColor color, double maximum, QWidget* parent) : QWidget(parent), color_(color), maximum_(maximum) {
        setMinimumHeight(46);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }
    void push(double v) {
        values_.push_back(std::max(0.0, v));
        while (values_.size() > 60) values_.pop_front();
        update();
    }
    void clear() {
        values_.clear();
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const QRectF r = QRectF(rect()).adjusted(1, 3, -1, -2);
        p.setPen(QPen(QColor(255, 255, 255, 18), 1));
        p.drawLine(r.bottomLeft(), r.bottomRight());
        if (values_.size() < 2) return;
        double top = maximum_;
        if (top <= 0) top = std::max(1.0, *std::max_element(values_.begin(), values_.end()) * 1.15);   // auto scale
        QPainterPath line;
        const double step = r.width() / 59.0;
        const double x0 = r.right() - step * double(values_.size() - 1);
        for (std::size_t i = 0; i < values_.size(); ++i) {
            const QPointF pt(x0 + step * double(i), r.bottom() - r.height() * std::min(1.0, values_[i] / top));
            if (i == 0) line.moveTo(pt);
            else line.lineTo(pt);
        }
        QPainterPath fill = line;
        fill.lineTo(r.right(), r.bottom());
        fill.lineTo(x0, r.bottom());
        fill.closeSubpath();
        QColor area = color_;
        area.setAlpha(40);
        p.fillPath(fill, area);
        p.setPen(QPen(color_, 1.6));
        p.drawPath(line);
    }

private:
    QColor color_;
    double maximum_;
    std::deque<double> values_;
};

namespace {

QString bytesText(qint64 bytes) { return QLocale().formattedDataSize(bytes, 1, QLocale::DataSizeTraditionalFormat); }

QString percent(double v) { return QLocale().toString(v, 'f', v < 10 ? 1 : 0) + QStringLiteral("%"); }

struct Tile {
    QLabel* value;
    QLabel* sub;
    Sparkline* line;
};

Tile makeTile(QGridLayout* grid, int row, int col, const QString& title, const QColor& color, double maximum, QWidget* parent) {
    auto* card = new Card(title, parent);
    Tile t;
    t.value = new QLabel(QStringLiteral("—"), card);
    t.value->setStyleSheet(QStringLiteral("font-size: 22pt; font-weight: 600;"));   // the theme sets label fonts
    t.sub = mutedLabel(QStringLiteral("Medindo…"), card);
    t.line = new Sparkline(color, maximum, card);
    card->body()->addWidget(t.value);
    card->body()->addWidget(t.sub);
    card->body()->addWidget(t.line);
    grid->addWidget(card, row, col);
    return t;
}

QTableWidgetItem* cell(const QString& text, bool right = false) {
    auto* item = new QTableWidgetItem(text);
    if (right) item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    return item;
}

}  // namespace

PerformancePage::PerformancePage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);
    col->addWidget(mutedLabel(QStringLiteral("Medições do próprio Windows, atualizadas a cada segundo enquanto esta página está "
                                             "aberta. Nada é alterado no sistema."),
                              content));
    auto* grid = new QGridLayout;
    grid->setSpacing(16);
    const Tile cpu = makeTile(grid, 0, 0, QStringLiteral("Processador"), palette::Accent, 100, content);
    const Tile mem = makeTile(grid, 0, 1, QStringLiteral("Memória"), palette::Success, 100, content);
    const Tile gpu = makeTile(grid, 1, 0, QStringLiteral("Placa de vídeo"), palette::Medium, 100, content);
    const Tile disk = makeTile(grid, 1, 1, QStringLiteral("Disco"), palette::Muted, 0, content);
    cpuValue_ = cpu.value;
    cpuSub_ = cpu.sub;
    cpuLine_ = cpu.line;
    memValue_ = mem.value;
    memSub_ = mem.sub;
    memLine_ = mem.line;
    gpuValue_ = gpu.value;
    gpuSub_ = gpu.sub;
    gpuLine_ = gpu.line;
    diskValue_ = disk.value;
    diskSub_ = disk.sub;
    diskLine_ = disk.line;
    col->addLayout(grid);

    auto* procs = new Card(QStringLiteral("O que mais está usando agora"), content);
    auto* head = new QHBoxLayout;
    head->addWidget(mutedLabel(QStringLiteral("Feche o que você não precisa antes de jogar."), procs), 1);
    head->addWidget(new QLabel(QStringLiteral("Ordenar por"), procs));
    sortBy_ = new QComboBox(procs);
    sortBy_->addItem(QStringLiteral("Processador"), QStringLiteral("cpu"));
    sortBy_->addItem(QStringLiteral("Memória"), QStringLiteral("memory"));
    sortBy_->addItem(QStringLiteral("Placa de vídeo"), QStringLiteral("gpu"));
    head->addWidget(sortBy_);
    procs->body()->addLayout(head);
    table_ = makeTable({"Programa", "PID", "Processador", "Placa de vídeo", "Memória"}, procs);
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    procs->body()->addWidget(table_);
    empty_ = mutedLabel(QString(), procs);
    empty_->setVisible(false);
    procs->body()->addWidget(empty_);
    notes_ = mutedLabel(QString(), procs);
    procs->body()->addWidget(notes_);
    col->addWidget(procs);
    col->addStretch();

    connect(ctx_->performance(), &gk::bridge::PerformanceService::sampled, this, [this](const QJsonObject& s) {
        if (sampling_) display(s);
    });
    connect(sortBy_, &QComboBox::currentIndexChanged, this, [this] { fillProcesses(); });
}

void PerformancePage::showEvent(QShowEvent* event) {
    QWidget::showEvent(event);
    setSampling(true);
}

void PerformancePage::hideEvent(QHideEvent* event) {
    QWidget::hideEvent(event);
    setSampling(false);   // no measuring while nobody looks
}

void PerformancePage::setSampling(bool on) {
    if (on == sampling_) return;
    sampling_ = on;
    if (on) ctx_->performance()->start(1000);
    else ctx_->performance()->stop();
}

void PerformancePage::display(const QJsonObject& s) {
    last_ = s;
    ++samples_;
    const int cpus = s.value("logical_cpus").toInt();
    if (s.value("cpu_percent").isDouble()) {
        const double v = s.value("cpu_percent").toDouble();
        cpuValue_->setText(percent(v));
        cpuLine_->push(v);
    }
    cpuSub_->setText(QStringLiteral("%1 processadores lógicos").arg(cpus));

    const qint64 total = s.value("memory_total").toInteger(), avail = s.value("memory_available").toInteger();
    if (total > 0) {
        const double used = 100.0 * double(total - avail) / double(total);
        memValue_->setText(percent(used));
        memSub_->setText(QStringLiteral("%1 em uso de %2 (%3 livres)").arg(bytesText(total - avail), bytesText(total), bytesText(avail)));
        memLine_->push(used);
    }

    const QJsonArray gpus = s.value("gpus").toArray();
    if (gpus.isEmpty()) {
        gpuValue_->setText(QStringLiteral("—"));
        QString why;
        for (const auto& u : s.value("unavailable").toArray())
            if (u.toString().startsWith(QLatin1String("GPU"))) why = u.toString().mid(5);
        gpuSub_->setText(why.isEmpty() ? QStringLiteral("Sem medição da placa de vídeo.") : QStringLiteral("Indisponível: %1").arg(why));
    } else {
        QStringList lines;
        double busiest = -1;
        for (const auto& v : gpus) {
            const QJsonObject g = v.toObject();
            busiest = std::max(busiest, g.value("utilization").toDouble(-1));
            QString line = g.value("name").toString();
            if (g.value("dedicated_used").isDouble())
                line += QStringLiteral(" — memória de vídeo: %1 de %2").arg(bytesText(g.value("dedicated_used").toInteger()),
                                                                          bytesText(g.value("dedicated_total").toInteger()));
            else if (g.value("dedicated_total").toInteger() > 0)
                line += QStringLiteral(" — %1 de memória de vídeo").arg(bytesText(g.value("dedicated_total").toInteger()));
            lines << line;
        }
        gpuValue_->setText(busiest >= 0 ? percent(busiest) : QStringLiteral("—"));
        gpuSub_->setText(lines.join('\n'));
        if (busiest >= 0) gpuLine_->push(busiest);
    }

    if (s.value("disk_read_bps").isDouble()) {
        const double r = s.value("disk_read_bps").toDouble(), w = s.value("disk_write_bps").toDouble();
        diskValue_->setText(bytesText(qint64(r + w)) + QStringLiteral("/s"));
        diskSub_->setText(QStringLiteral("leitura %1/s · gravação %2/s").arg(bytesText(qint64(r)), bytesText(qint64(w))));
        diskLine_->push(r + w);
    } else {
        QString why;
        for (const auto& u : s.value("unavailable").toArray())
            if (u.toString().startsWith(QLatin1String("disco"))) why = u.toString().mid(7);
        if (!why.isEmpty()) diskSub_->setText(QStringLiteral("Indisponível: %1").arg(why));
    }

    fillProcesses();
    const QJsonObject self = s.value("self").toObject();
    QStringList notes;
    notes << QStringLiteral("O Game Kernel usa %1 do processador e %2 de memória.")
                 .arg(self.value("cpu_percent").isDouble() ? percent(self.value("cpu_percent").toDouble()) : QStringLiteral("—"),
                      bytesText(self.value("memory_bytes").toInteger()));
    notes << QStringLiteral("%1 processos em execução%2.")
                 .arg(s.value("processes").toInt())
                 .arg(s.value("unmeasured").toInt() > 0
                          ? QStringLiteral("; %1 protegidos pelo Windows não puderam ser medidos").arg(s.value("unmeasured").toInt())
                          : QString());
    notes_->setText(notes.join(' '));
    emit updated(s);
}

void PerformancePage::fillProcesses() {
    const QString key = sortBy_->currentData().toString();
    const QJsonArray list = last_.value(key == QLatin1String("memory") ? "top_memory" : key == QLatin1String("gpu") ? "top_gpu" : "top_cpu").toArray();
    table_->setRowCount(0);
    for (const auto& v : list) {
        const QJsonObject p = v.toObject();
        const int row = table_->rowCount();
        table_->insertRow(row);
        table_->setItem(row, 0, cell(p.value("name").toString()));
        table_->setItem(row, 1, cell(QString::number(p.value("pid").toInteger()), true));
        table_->setItem(row, 2, cell(p.value("cpu_percent").isDouble() ? percent(p.value("cpu_percent").toDouble()) : QStringLiteral("—"), true));
        table_->setItem(row, 3, cell(p.value("gpu_percent").isDouble() ? percent(p.value("gpu_percent").toDouble()) : QStringLiteral("—"), true));
        table_->setItem(row, 4, cell(bytesText(p.value("memory_bytes").toInteger()), true));
    }
    fitTableToContents(table_, 8);
    table_->setVisible(table_->rowCount() > 0);
    empty_->setVisible(table_->rowCount() == 0);
    empty_->setText(key == QLatin1String("gpu") ? QStringLiteral("Nenhum programa usou a placa de vídeo no último segundo.")
                    : key == QLatin1String("memory") ? QStringLiteral("Lista de programas indisponível.")
                                                      : QStringLiteral("Nenhum programa usou o processador no último segundo."));
}

void PerformancePage::sortProcessesBy(const QString& key) {
    const int i = sortBy_->findData(key);
    if (i >= 0) sortBy_->setCurrentIndex(i);
}

QString PerformancePage::cpuText() const { return cpuValue_->text() + QStringLiteral(" — ") + cpuSub_->text(); }
QString PerformancePage::memoryText() const { return memValue_->text() + QStringLiteral(" — ") + memSub_->text(); }
QString PerformancePage::gpuText() const { return gpuValue_->text() + QStringLiteral(" — ") + gpuSub_->text(); }
QString PerformancePage::diskText() const { return diskValue_->text() + QStringLiteral(" — ") + diskSub_->text(); }
QString PerformancePage::notesText() const { return notes_->text(); }
int PerformancePage::processRows() const { return table_->rowCount(); }
QString PerformancePage::processesEmptyText() const { return empty_->isVisibleTo(this) ? empty_->text() : QString(); }

}  // namespace gk::app
