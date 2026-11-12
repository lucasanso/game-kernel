"""PDF rendering of a ``gamekernel-report`` with ReportLab (fully offline).

A Unicode TrueType font is registered when available (Segoe UI/Arial on Windows, DejaVu
Sans on Linux) so paths with non-Latin characters render correctly; otherwise the built-in
Helvetica is used and characters outside Windows-1252 are replaced (reported as a warning).
"""

from __future__ import annotations

import io
import os
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .report_html import _size

RISK_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"), "HIGH": colors.HexColor("#ea580c"), "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#ca8a04"), "INFO": colors.HexColor("#64748b"), "NONE": colors.HexColor("#94a3b8"),
}
ACCENT = colors.HexColor("#1f6feb")
MUTED = colors.HexColor("#5b6472")

_FONT_CANDIDATES = [
    (os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "segoeui.ttf"),
     os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "segoeuib.ttf")),
    (os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "arial.ttf"),
     os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "arialbd.ttf")),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/TTF/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"),
]
_FONTS: tuple[str, str, bool] | None = None


def _fonts() -> tuple[str, str, bool]:
    """Return (regular, bold, unicode_capable)."""
    global _FONTS
    if _FONTS is None:
        _FONTS = ("Helvetica", "Helvetica-Bold", False)
        for regular, bold in _FONT_CANDIDATES:
            if os.path.isfile(regular) and os.path.isfile(bold):
                try:
                    pdfmetrics.registerFont(TTFont("GK-Regular", regular))
                    pdfmetrics.registerFont(TTFont("GK-Bold", bold))
                    _FONTS = ("GK-Regular", "GK-Bold", True)
                    break
                except Exception:  # unreadable/corrupt font file: try the next one
                    continue
    return _FONTS


class _Renderer:
    def __init__(self) -> None:
        regular, bold, self.unicode = _fonts()
        self.lossy = False
        self.s = {
            "title": ParagraphStyle("t", fontName=bold, fontSize=17, leading=21, textColor=ACCENT, spaceAfter=4),
            "h2": ParagraphStyle("h2", fontName=bold, fontSize=12.5, leading=16, spaceBefore=12, spaceAfter=5,
                                 textColor=ACCENT),
            "h3": ParagraphStyle("h3", fontName=bold, fontSize=10.5, leading=13, spaceBefore=4, spaceAfter=2,
                                 wordWrap="CJK"),
            "body": ParagraphStyle("b", fontName=regular, fontSize=8.8, leading=11.2, alignment=TA_LEFT),
            "muted": ParagraphStyle("m", fontName=regular, fontSize=8, leading=10, textColor=MUTED),
            "key": ParagraphStyle("k", fontName=bold, fontSize=8.3, leading=10.5, textColor=MUTED),
            "mono": ParagraphStyle("mono", fontName=regular, fontSize=8, leading=10, wordWrap="CJK"),
        }

    def t(self, value: Any) -> str:
        text = "" if value is None else str(value)
        if not self.unicode:
            encoded = text.encode("cp1252", errors="replace").decode("cp1252")
            if encoded != text:
                self.lossy = True
            text = encoded
        return escape(text)

    def p(self, value: Any, style: str = "body") -> Paragraph:
        return Paragraph(self.t(value), self.s[style])

    def kv(self, pairs: list[tuple[str, Any]], mono: tuple[str, ...] = ()) -> Table | Spacer:
        rows = [[self.p(k, "key"), self.p(v, "mono" if k in mono else "body")] for k, v in pairs
                if v not in (None, "", [])]
        if not rows:
            return Spacer(1, 1)
        table = Table(rows, colWidths=[42 * mm, None])
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dde1e7")),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        return table

    def bullets(self, items: list[str]) -> list:
        return [Paragraph("• " + self.t(i), self.s["body"]) for i in items]

    def risk_header(self, level: str, label: str, name: str) -> Table:
        color = RISK_COLORS.get(level, RISK_COLORS["INFO"])
        cell = Paragraph(f"<font color='#ffffff'><b>{self.t(label)}</b></font>", self.s["body"])
        table = Table([[cell, Paragraph(self.t(name), self.s["h3"])]], colWidths=[26 * mm, None])
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), color), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                   ("LEFTPADDING", (0, 0), (0, 0), 4)]))
        return table

    def evidence(self, ev: dict) -> list:
        out = [Paragraph(
            f"<b>[{self.t(ev['effective_severity_label'])}] {self.t(ev['title'])}</b> — {self.t(ev['source_label'])}; "
            f"regra {self.t(ev['rule_id'])}; confiança {self.t(ev['confidence_label'])}; {self.t(ev['category_label'])}",
            self.s["body"])]
        if ev.get("description"):
            out.append(self.p(ev["description"], "muted"))
        for loc in ev.get("locations") or []:
            text = loc.get("summary") or ""
            if loc.get("excerpt"):
                text += f" — {loc['excerpt']}"
            out.append(self.p("  ↳ " + text, "mono"))
        if ev.get("generic_indicator"):
            out.append(self.p("Indicador genérico: aponta uma técnica ou capacidade, não o código malicioso exato.",
                              "muted"))
        if ev.get("adjustment_reason"):
            out.append(self.p(f"Severidade ajustada ({ev['severity_label']} → {ev['effective_severity_label']}): "
                              f"{ev['adjustment_reason']}", "muted"))
        if ev.get("fp_note"):
            out.append(self.p(f"Possível falso positivo: {ev['fp_note']}", "muted"))
        return out

    def file_block(self, f: dict, threat_info: bool = True) -> list:
        sig = (f"válida — {f['signer']}" if f.get("signature_valid") else
               "presente, inválida" if f.get("signed") else "ausente")
        flow = [self.risk_header(f["risk"], f["risk_label"], f["name"]), self.kv([
            ("Caminho completo", f["path"]), ("Arquivo físico", f["physical_file"] if f.get("container") else None),
            ("Pasta de origem", f.get("directory")), ("Extensão", f.get("extension")),
            ("Tamanho", f"{_size(f.get('size'))} ({f.get('size')} bytes)" if f.get("size") is not None else None),
            ("SHA-256", f.get("sha256")), ("Tipo real", f.get("file_type")),
            ("Classificação", f.get("classification_label")), ("Categoria", f.get("category_label")),
            ("Detecções", ", ".join(f.get("detections") or [])), ("Assinatura digital", sig),
            ("Analisado em", f.get("analyzed_at")),
        ], mono=("Caminho completo", "Arquivo físico", "Pasta de origem", "SHA-256"))]
        info = f.get("threat_info") if threat_info else None
        if info:
            flow.append(self.kv([("O que pode fazer", info["can_do"]), ("Informações em risco", info["data_at_risk"]),
                                 ("Limitações", info["limitations"])]))
        if f.get("explanation"):
            flow.append(self.p("Como o nível de risco foi definido:", "key"))
            flow += self.bullets(f["explanation"])
        for ev in f.get("evidences") or []:
            flow += self.evidence(ev)
        if f.get("possible_false_positive"):
            flow.append(self.p("Falso positivo possível: " + " ".join(f.get("fp_notes") or []), "muted"))
        if f.get("recommendations"):
            flow.append(self.p("Ações recomendadas:", "key"))
            flow += self.bullets(f["recommendations"])
        flow.append(Spacer(1, 6))
        return flow


def render_pdf(r: dict[str, Any]) -> tuple[bytes, list[str]]:
    R = _Renderer()
    scan, counts, comp = r["scan"], r["counts"], r["computer"]
    story: list = [R.p("Relatório forense — Game Kernel", "title"),
                   R.p(f"Varredura nº {scan['id']} · gerado em {r['generated_at']} · "
                       f"{r['generator']['application']} {r['generator']['version']}", "muted"),
                   Spacer(1, 4),
                   R.risk_header(r["max_risk"]["level"], r["max_risk"]["label"], r["max_risk"]["meaning"])]

    def h(num: int, title: str) -> None:
        story.append(R.p(f"{num}. {title}", "h2"))

    os_info = comp.get("os", {})
    h(1, "Informações gerais do computador")
    story.append(R.kv([
        ("Sistema operacional", f"{os_info.get('product', '')} {os_info.get('edition') or ''} ({os_info.get('version')})"),
        ("Suporte", os_info.get("support_note")), ("Arquitetura", comp.get("architecture")),
        ("Processador", f"{comp['cpu']['model']} — {comp['cpu']['logical_cores']} núcleos lógicos"),
        ("Memória total", _size(comp.get("memory_total_bytes"))), ("Nome do computador", comp.get("hostname")),
    ]))
    h(2, "Pasta(s) analisada(s)")
    story += R.bullets(scan["targets"])
    story.append(R.kv([("Modo", scan["mode_label"]), ("Rótulo", scan["label"]), ("Origem", scan["origin"])]))
    h(3, "Data e duração da análise")
    story.append(R.kv([("Início", scan["started_at"]), ("Término", scan["finished_at"]),
                       ("Duração", f"{scan['duration_seconds']} s"), ("Estado", scan["status_label"]),
                       ("Erro", scan.get("error"))]))
    h(4, "Arquivos encontrados")
    story.append(R.kv([
        ("Encontrados", counts["files_found"]), ("Membros de compactados", counts["members_analyzed"]),
        ("Volume verificado", _size(counts["bytes_scanned"])), ("Ameaças", counts["threats"]),
        ("Suspeitos", counts["suspicious"]), ("Potencialmente indesejados", counts["pua"]),
        ("Falsos positivos possíveis", counts["possible_false_positives"]), ("Cracks", counts["cracks"]),
    ]))
    h(5, "Arquivos examinados")
    story.append(R.kv([("Examinados", counts["files_analyzed"]), ("Sem indicadores de risco", counts["clean"])]))
    h(6, "Arquivos não examinados")
    if r["not_examined"]:
        for n in r["not_examined"]:
            story.append(R.p(f"{n['path']} — {n['status_label']}: {'; '.join(n.get('reasons') or []) or '—'}", "mono"))
    else:
        story.append(R.p("Todos os arquivos selecionados foram examinados.", "muted"))
    h(7, "Ameaças detectadas")
    for f in r["threats"]:
        story += R.file_block(f)
    if not r["threats"]:
        story.append(R.p("Nenhuma ameaça detectada.", "muted"))
    h(8, "Arquivos suspeitos e potencialmente indesejados")
    for f in r["suspicious"] + r["pua"]:
        story += R.file_block(f)
    if not (r["suspicious"] or r["pua"]):
        story.append(R.p("Nenhum arquivo suspeito.", "muted"))
    h(9, "Outras evidências técnicas")
    for f in r["other_findings"]:
        story += R.file_block(f, threat_info=False)
    if not r["other_findings"]:
        story.append(R.p("Nenhuma outra ocorrência.", "muted"))
    h(10, "Relatório individual de cracks")
    for c in r["cracks"]:
        story.append(KeepTogether([
            R.risk_header(c["risk"], c["crack_status_label"], c["name"]),
            R.kv([("Localização", c["path"]), ("SHA-256", c.get("sha256")),
                  ("Tipo de modificação", "; ".join(c.get("modification_types") or [])),
                  ("Assinatura digital", (f"válida — {c['signer']}" if c.get("signature_valid") else
                                          "presente, inválida" if c.get("signed") else "ausente")),
                  ("Riscos potenciais", ", ".join(c.get("potential_risks") or []) or "nenhum identificado"),
                  ("Falso positivo possível", "sim" if c.get("possible_false_positive") else "não indicado"),
                  ("Recomendação", c.get("crack_recommendation"))], mono=("Localização", "SHA-256")),
            Spacer(1, 6)]))
    if not r["cracks"]:
        story.append(R.p("Nenhum componente de crack identificado.", "muted"))
    h(11, "Escala de risco")
    for s in r["risk_scale"]:
        story.append(R.p(f"{s['label']}: {s['meaning']}"))
    story.append(R.p("Os níveis são qualitativos e não representam probabilidade de infecção.", "muted"))
    h(12, "Mecanismos e assinaturas")
    for e in r.get("engines") or []:
        story.append(R.p(f"{e.get('name')}: {'disponível' if e.get('available') else 'indisponível'} "
                         f"{e.get('version') or ''} {e.get('detail') or ''}"))
    sig = r.get("signatures") or {}
    if sig:
        story.append(R.kv([("Assinaturas ClamAV", sig.get("clamav_signature_count")),
                           ("Regras YARA", sig.get("yara_rule_count")), ("IOC", sig.get("ioc_count")),
                           ("Desatualizadas", ("sim — " + (sig.get("stale_reason") or "")) if sig.get("stale") else "não")]))
    h(13, "Recomendações")
    story += R.bullets(r["recommendations"])
    h(14, "Limitações da análise")
    story += R.bullets(r["limitations"] + list(r.get("warnings") or []))
    story.append(Spacer(1, 8))
    story.append(R.p(r["privacy"]["note"], "muted"))

    buffer = io.BytesIO()

    def footer(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont(R.s["muted"].fontName, 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(15 * mm, 9 * mm, f"Game Kernel — varredura {scan['id']}")
        canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"página {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm,
                            bottomMargin=16 * mm, title=f"Relatório Game Kernel — varredura {scan['id']}",
                            author="Game Kernel", creator="Game Kernel", invariant=1)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    warnings = []
    if R.lossy:
        warnings.append("Nenhuma fonte Unicode disponível para o PDF; alguns caracteres foram substituídos por '?'. "
                        "O relatório HTML/JSON contém os nomes exatos.")
    return buffer.getvalue(), warnings
