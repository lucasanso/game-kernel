#include "ui_kit.hpp"

#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QHeaderView>
#include <QTableWidget>
#include <QHash>
#include <QPainter>
#include <QPalette>
#include <QPixmap>
#include <QStyleFactory>
#include <QSvgRenderer>
#include <QVBoxLayout>

namespace gk::app {

namespace {

QString hex(const QColor& c) { return c.name(QColor::HexRgb); }

// 24×24 stroke icons (own drawings; "currentColor" is replaced at render time).
const QHash<QString, QString>& iconPaths() {
    static const QHash<QString, QString> paths{
        {"shield", "<path d='M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z'/>"},
        {"shield-check", "<path d='M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z'/><path d='M8.5 12l2.5 2.5 4.5-5'/>"},
        {"package", "<path d='M21 8l-9-5-9 5 9 5z'/><path d='M3 8v8l9 5 9-5V8'/><path d='M12 13v8'/>"},
        {"flask", "<path d='M9 3h6'/><path d='M10 3v6l-5.2 8.7A2 2 0 0 0 6.5 21h11a2 2 0 0 0 1.7-3.3L14 9V3'/><path d='M7.5 15h9'/>"},
        {"lock", "<rect x='5' y='11' width='14' height='10' rx='2'/><path d='M8 11V8a4 4 0 0 1 8 0v3'/>"},
        {"key", "<circle cx='8' cy='15' r='4'/><path d='M11 12l9-9'/><path d='M17 6l3 3'/>"},
        {"rotate-ccw", "<path d='M3 4v6h6'/><path d='M3.5 15a9 9 0 1 0 2.1-9.4L3 10'/>"},
        {"refresh", "<path d='M21 4v6h-6'/><path d='M20.5 15a9 9 0 1 1-2.1-9.4L21 10'/>"},
        {"upload", "<path d='M12 16V4'/><path d='M7 9l5-5 5 5'/><path d='M4 20h16'/>"},
        {"file", "<path d='M14 3H6v18h12V7z'/><path d='M14 3v4h4'/>"},
        {"check", "<path d='M5 12.5l4.5 4.5L19 7.5'/>"},
        {"alert", "<path d='M12 3l10 18H2z'/><path d='M12 10v5'/><path d='M12 18h.01'/>"},
        {"info", "<circle cx='12' cy='12' r='9'/><path d='M12 11v6'/><path d='M12 7.5h.01'/>"},
        {"x", "<path d='M6 6l12 12'/><path d='M18 6L6 18'/>"},
        {"wifi-off", "<path d='M2 2l20 20'/><path d='M8.5 16.5a5 5 0 0 1 7 0'/><path d='M5 13a10 10 0 0 1 5.2-2.8'/><path d='M19 13a10 10 0 0 0-2.2-1.6'/><path d='M12 20h.01'/>"},
        {"play", "<path d='M7 4l13 8-13 8z'/>"},
        {"stop", "<rect x='6' y='6' width='12' height='12' rx='1'/>"},
        {"trash", "<path d='M4 7h16'/><path d='M9 7V4h6v3'/><path d='M6 7l1 14h10l1-14'/>"},
    };
    return paths;
}

QPixmap renderSvg(const QByteArray& svg, int size) {
    QSvgRenderer renderer(svg);
    QPixmap pm(size, size);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    renderer.render(&p);
    return pm;
}

}  // namespace

QColor riskColor(const QString& level) {
    const QString l = level.toUpper();
    if (l == "CRITICAL") return palette::Critical;
    if (l == "HIGH") return palette::High;
    if (l == "MEDIUM") return palette::Medium;
    if (l == "LOW") return palette::Low;
    if (l == "INFO") return palette::Info;
    return palette::Muted;
}

QString riskLabel(const QString& level) {
    static const QHash<QString, QString> labels{{"CRITICAL", "Crítico"}, {"HIGH", "Alto"},       {"MEDIUM", "Médio"},
                                                {"LOW", "Baixo"},        {"INFO", "Informativo"}, {"NONE", "Nenhum"}};
    return labels.value(level.toUpper(), level);
}

QStringList iconNames() { return iconPaths().keys(); }

QIcon icon(const QString& name, const QColor& color, int size) {
    const auto it = iconPaths().constFind(name);
    if (it == iconPaths().constEnd()) return {};
    const QString svg = QStringLiteral("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' "
                                       "stroke='%1' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'>%2</svg>")
                            .arg(hex(color), it.value());
    QIcon result;
    for (int s : {size, size * 2}) result.addPixmap(renderSvg(svg.toUtf8(), s));
    return result;
}

QIcon appIcon() {
    // Shield with a gradient (blue → green) and a "kernel" chip in the centre.
    static const QByteArray svg =
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>"
        "<defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>"
        "<stop offset='0' stop-color='#3B82F6'/><stop offset='1' stop-color='#22C55E'/></linearGradient></defs>"
        "<path d='M32 4l22 9v15c0 14-9.5 25.5-22 31C19.5 53.5 10 42 10 28V13z' fill='url(#g)'/>"
        "<path d='M32 9l17 7v12c0 11.5-7.4 21-17 25.6C22.4 49 15 39.5 15 28V16z' fill='#0E1116'/>"
        "<rect x='23' y='20' width='18' height='18' rx='3' fill='none' stroke='#E6EAF0' stroke-width='3'/>"
        "<path d='M27 20v-4M32 20v-4M37 20v-4M27 38v4M32 38v4M37 38v4M23 25h-4M23 29h-4M23 33h-4M41 25h4M41 29h4M41 33h4' "
        "stroke='#E6EAF0' stroke-width='2.4' stroke-linecap='round'/>"
        "<path d='M28 29.5l3 3 5-6' fill='none' stroke='#22C55E' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'/>"
        "</svg>";
    QIcon result;
    for (int s : {16, 24, 32, 48, 64, 128, 256}) result.addPixmap(renderSvg(svg, s));
    return result;
}

QString styleSheet() {
    using namespace palette;
    return QStringLiteral(R"(
* { color: %1; font-size: 13px; }
QMainWindow, QDialog, QWidget#page { background: %2; }
QWidget#sidebar { background: %3; border-right: 1px solid %4; }
QLabel#brand { font-size: 17px; font-weight: 700; }
QLabel#version, QLabel[muted="true"] { color: %5; }
QLabel#pageTitle { font-size: 21px; font-weight: 700; }
QLabel#pageSubtitle { color: %5; }
QLabel#cardTitle { font-size: 14px; font-weight: 600; }
QLabel#metric { font-size: 20px; font-weight: 700; }
QListWidget#nav { background: transparent; border: none; outline: 0; }
QListWidget#nav::item { padding: 10px 12px; margin: 2px 8px; border-radius: 8px; color: %5; }
QListWidget#nav::item:hover { background: %6; color: %1; }
QListWidget#nav::item:selected { background: %6; color: %1; border-left: 3px solid %7; }
QFrame#card { background: %3; border: 1px solid %4; border-radius: 12px; }
QPushButton { background: %6; border: 1px solid %4; border-radius: 8px; padding: 7px 14px; }
QPushButton:hover { border-color: %7; }
QPushButton:pressed { background: %4; }
QPushButton:disabled { color: %5; background: %3; border-color: %4; }
QPushButton[primary="true"] { background: %7; border-color: %7; color: white; font-weight: 600; }
QPushButton[primary="true"]:hover { background: #2F6FDB; }
QPushButton[primary="true"]:disabled { background: %4; border-color: %4; color: %5; }
QPushButton[danger="true"] { border-color: %8; color: %8; }
QPushButton[danger="true"]:disabled { border-color: %4; color: %5; }
QTableWidget, QTreeWidget, QListWidget, QPlainTextEdit, QTextBrowser {
  background: %2; border: 1px solid %4; border-radius: 8px; gridline-color: %4;
  selection-background-color: #233552; selection-color: %1; }
QTableWidget { alternate-background-color: %3; }
QTableWidget::item { padding: 4px 10px; border: none; }
QHeaderView::section { background: %3; color: %5; border: none; border-bottom: 1px solid %4; padding: 6px 10px; font-weight: 600; }
QLineEdit, QSpinBox { background: %2; border: 1px solid %4; border-radius: 8px; padding: 6px 8px; }
QLineEdit:focus, QSpinBox:focus { border-color: %7; }
QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid %4; background: %2; }
QCheckBox::indicator:checked { background: %7; border-color: %7; }
QProgressBar { background: %2; border: 1px solid %4; border-radius: 6px; height: 10px; text-align: center; }
QProgressBar::chunk { background: %7; border-radius: 6px; }
QScrollArea { background: transparent; border: none; }
QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background: %4; border-radius: 5px; min-height: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QToolTip { background: %6; color: %1; border: 1px solid %4; padding: 6px; }
QFrame#toast { background: %6; border: 1px solid %4; border-radius: 10px; }
)")
        .arg(hex(Text), hex(Background), hex(Surface), hex(Border), hex(Muted), hex(SurfaceRaised), hex(Accent),
             hex(Critical));
}

void applyTheme() {
    QApplication::setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    QPalette pal;
    pal.setColor(QPalette::Window, palette::Background);
    pal.setColor(QPalette::WindowText, palette::Text);
    pal.setColor(QPalette::Base, palette::Background);
    pal.setColor(QPalette::AlternateBase, palette::Surface);
    pal.setColor(QPalette::Text, palette::Text);
    pal.setColor(QPalette::Button, palette::SurfaceRaised);
    pal.setColor(QPalette::ButtonText, palette::Text);
    pal.setColor(QPalette::Highlight, palette::Accent);
    pal.setColor(QPalette::HighlightedText, Qt::white);
    pal.setColor(QPalette::PlaceholderText, palette::Muted);
    QApplication::setPalette(pal);
    QFont font = QApplication::font();
    font.setFamilies({QStringLiteral("Segoe UI"), QStringLiteral("Inter"), QStringLiteral("DejaVu Sans")});
    QApplication::setFont(font);
    qApp->setStyleSheet(styleSheet());
    QApplication::setWindowIcon(appIcon());
}

QTableWidget* makeTable(const QStringList& headers, QWidget* parent) {
    auto* t = new QTableWidget(0, int(headers.size()), parent);
    t->setHorizontalHeaderLabels(headers);
    t->verticalHeader()->setVisible(false);
    t->setShowGrid(false);
    t->setAlternatingRowColors(true);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setWordWrap(true);
    // Columns follow their content; the last one fills the remaining width.
    for (int c = 0; c + 1 < int(headers.size()); ++c)
        t->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    t->horizontalHeader()->setSectionResizeMode(int(headers.size()) - 1, QHeaderView::Stretch);
    t->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    fitTableToContents(t);
    return t;
}

void fitTableToContents(QTableWidget* table, int maxRows) {
    table->resizeRowsToContents();
    int height = table->horizontalHeader()->sizeHint().height() + 2 * table->frameWidth() + 4;
    const int rows = qMin(table->rowCount(), maxRows);
    for (int r = 0; r < rows; ++r) height += table->rowHeight(r);
    if (rows == 0) height += 34;
    table->setFixedHeight(height);
}

Card::Card(const QString& title, QWidget* parent) : QFrame(parent) {
    setObjectName(QStringLiteral("card"));
    body_ = new QVBoxLayout(this);
    body_->setContentsMargins(18, 16, 18, 16);
    body_->setSpacing(10);
    if (!title.isEmpty()) {
        auto* label = new QLabel(title, this);
        label->setObjectName(QStringLiteral("cardTitle"));
        body_->addWidget(label);
    }
}

StatusPill::StatusPill(const QString& text, Tone tone, QWidget* parent) : QLabel(parent) { set(text, tone); }

void StatusPill::set(const QString& text, Tone tone) {
    tone_ = tone;
    setText(text);
    QColor c = palette::Muted;
    switch (tone) {
        case Tone::Good: c = palette::Success; break;
        case Tone::Warning: c = palette::Medium; break;
        case Tone::Bad: c = palette::Critical; break;
        case Tone::Accent: c = palette::Accent; break;
        case Tone::Neutral: break;
    }
    setStyleSheet(QStringLiteral("QLabel { color: %1; background: %2; border: 1px solid %1; border-radius: 10px; "
                                 "padding: 2px 10px; font-weight: 600; }")
                      .arg(c.name(), QColor(c.red(), c.green(), c.blue(), 38).name(QColor::HexArgb)));
}

}  // namespace gk::app
