// Visual identity of the Game Kernel desktop application: palette tokens, style sheet, icons and a
// few reusable widgets. Dark graphite background, blue/green accents, yellow/orange/red for risk.
#pragma once

#include <QColor>
#include <QFrame>
#include <QIcon>
#include <QLabel>
#include <QString>

class QVBoxLayout;
class QTableWidget;

namespace gk::app {

namespace palette {
inline const QColor Background{0x0E, 0x11, 0x16};
inline const QColor Surface{0x15, 0x1A, 0x21};
inline const QColor SurfaceRaised{0x1C, 0x23, 0x2D};
inline const QColor Border{0x26, 0x30, 0x40};
inline const QColor Text{0xE6, 0xEA, 0xF0};
inline const QColor Muted{0x93, 0xA1, 0xB3};
inline const QColor Accent{0x3B, 0x82, 0xF6};     // blue
inline const QColor Success{0x22, 0xC5, 0x5E};    // green
inline const QColor Low{0xEA, 0xB3, 0x08};        // yellow
inline const QColor Medium{0xF5, 0x9E, 0x0B};     // amber
inline const QColor High{0xF9, 0x73, 0x16};       // orange
inline const QColor Critical{0xEF, 0x44, 0x44};   // red
inline const QColor Info{0x64, 0x74, 0x8B};       // slate
}  // namespace palette

// Risk level names of the data contract (core/models.py RiskLevel) → colour and pt-BR label.
QColor riskColor(const QString& level);
QString riskLabel(const QString& level);

QString styleSheet();
void applyTheme();                         // palette + style sheet + font on the running QApplication

// Stroke icons drawn from inline SVG (no external files). Unknown names return a null icon.
QIcon icon(const QString& name, const QColor& color = palette::Text, int size = 20);
QStringList iconNames();
QIcon appIcon();                           // shield logo

// Read-only tables with the product look (no grid, alternating rows, row selection).
QTableWidget* makeTable(const QStringList& headers, QWidget* parent);
// Height follows the content (up to maxRows visible rows; at least one row tall when empty).
void fitTableToContents(QTableWidget* table, int maxRows = 10);

// A rounded panel with an optional title; content goes into body().
class Card : public QFrame {
    Q_OBJECT
public:
    explicit Card(const QString& title = {}, QWidget* parent = nullptr);
    QVBoxLayout* body() const { return body_; }

private:
    QVBoxLayout* body_;
};

// Small coloured status badge ("Ativo", "Indisponível", risk levels...).
class StatusPill : public QLabel {
    Q_OBJECT
public:
    enum class Tone { Neutral, Good, Warning, Bad, Accent };
    explicit StatusPill(const QString& text = {}, Tone tone = Tone::Neutral, QWidget* parent = nullptr);
    void set(const QString& text, Tone tone);
    Tone tone() const { return tone_; }

private:
    Tone tone_ = Tone::Neutral;
};

}  // namespace gk::app
