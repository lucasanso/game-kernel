"""Self-contained HTML rendering of a ``gamekernel-report`` (see report_engine.py).

Security properties: no JavaScript, no external resources (Content-Security-Policy
``default-src 'none'``), every value escaped — file names and evidence excerpts come from
untrusted files and must never be interpreted as markup.
"""

from __future__ import annotations

from html import escape
from typing import Any

RISK_CLASS = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info", "NONE": "none"}

CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--text:#14181f;--muted:#5b6472;--line:#dde1e7;--accent:#1f6feb;--ok:#16a34a;
--critical:#dc2626;--high:#ea580c;--medium:#d97706;--low:#ca8a04;--info:#64748b;--none:#94a3b8}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--panel:#161a21;--text:#e6e9ef;--muted:#9aa4b2;
--line:#262c36;--accent:#4c8dff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
header.top{border-bottom:3px solid var(--accent);padding-bottom:12px;margin-bottom:20px}
h1{font-size:24px;margin:0}h2{font-size:18px;margin:32px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{font-size:15px;margin:0 0 6px;word-break:break-all}.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.tile b{display:block;font-size:22px}.tile span{color:var(--muted);font-size:12px}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;
padding:12px 14px;margin:10px 0;break-inside:avoid}
.card.critical{border-left-color:var(--critical)}.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--medium)}.card.low{border-left-color:var(--low)}
.badge{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600;color:#fff;
background:var(--info)}.badge.critical{background:var(--critical)}.badge.high{background:var(--high)}
.badge.medium{background:var(--medium)}.badge.low{background:var(--low);color:#111}.badge.none{background:var(--none)}
.tag{display:inline-block;border:1px solid var(--line);border-radius:4px;padding:0 6px;font-size:12px;margin-right:4px}
table{width:100%;border-collapse:collapse;margin:6px 0}th,td{text-align:left;vertical-align:top;
border-bottom:1px solid var(--line);padding:5px 6px}th{width:190px;color:var(--muted);font-weight:600}
code,.mono{font-family:Consolas,"Cascadia Mono",Menlo,monospace;font-size:12.5px;word-break:break-all}
.ev{border-top:1px dashed var(--line);margin-top:8px;padding-top:8px}.fp{color:var(--muted);font-style:italic}
ul{margin:4px 0 4px 18px;padding:0}footer{margin-top:40px;color:var(--muted);font-size:12px}
@media print{body{background:#fff}.card,.tile{border-color:#bbb}}
"""


def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _size(n: int | None) -> str:
    if n is None:
        return "—"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _badge(level: str, label: str) -> str:
    return f'<span class="badge {RISK_CLASS.get(level, "info")}">{_e(label)}</span>'


def _rows(pairs: list[tuple[str, Any]], mono: tuple[str, ...] = ()) -> str:
    out = []
    for key, value in pairs:
        if value in (None, "", []):
            continue
        cell = f"<code>{_e(value)}</code>" if key in mono else _e(value)
        out.append(f"<tr><th>{_e(key)}</th><td>{cell}</td></tr>")
    return "<table>" + "".join(out) + "</table>"


def _list(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>" if items else ""


def _evidence(ev: dict) -> str:
    locs = []
    for loc in ev.get("locations") or []:
        excerpt = f' — <code>{_e(loc["excerpt"])}</code>' if loc.get("excerpt") else ""
        desc = f' ({_e(loc["description"])})' if loc.get("description") else ""
        locs.append(f"<li><span class='mono'>{_e(loc.get('summary'))}</span>{desc}{excerpt}</li>")
    generic = ("<div class='fp'>Indicador genérico: aponta uma técnica ou capacidade, não o código malicioso exato.</div>"
               if ev.get("generic_indicator") else "")
    adjust = (f"<div class='muted'>Severidade ajustada de {_e(ev['severity_label'])} para "
              f"{_e(ev['effective_severity_label'])}: {_e(ev['adjustment_reason'])}</div>"
              if ev.get("adjustment_reason") else "")
    fp = f"<div class='fp'>Possível falso positivo: {_e(ev['fp_note'])}</div>" if ev.get("fp_note") else ""
    return (
        f"<div class='ev'>{_badge(ev['effective_severity'], ev['effective_severity_label'])} "
        f"<b>{_e(ev['title'])}</b> <span class='tag'>{_e(ev['source_label'])}</span>"
        f"<span class='tag'>regra <code>{_e(ev['rule_id'])}</code></span>"
        f"<span class='tag'>confiança {_e(ev['confidence_label'])}</span>"
        f"<span class='tag'>{_e(ev['category_label'])}</span>"
        f"<div>{_e(ev.get('description'))}</div>"
        + (f"<div class='muted'>Localização da evidência dentro do arquivo:</div><ul>{''.join(locs)}</ul>" if locs else "")
        + generic + adjust + fp + "</div>"
    )


def _file_card(f: dict, show_threat_info: bool = True) -> str:
    member = f" (membro de {f['container']})" if f.get("container") else ""
    rows = _rows([
        ("Caminho completo", f["path"]),
        ("Arquivo físico", f["physical_file"] if f.get("container") else None),
        ("Caminho dentro do compactado", f.get("member_path")),
        ("Pasta de origem", f.get("directory")),
        ("Extensão", f.get("extension")),
        ("Tamanho", _size(f.get("size"))),
        ("SHA-256", f.get("sha256")),
        ("Tipo real", f.get("file_type")),
        ("Classificação", f.get("classification_label")),
        ("Categoria", f.get("category_label")),
        ("Detecções (regra/assinatura)", ", ".join(f.get("detections") or [])),
        ("Assinatura digital", (f"válida — {f['signer']}" if f.get("signature_valid") else
                                f"presente, inválida — {f.get('signer') or 'desconhecido'}" if f.get("signed") else
                                "ausente")),
        ("Estado do crack", f["crack_status_label"] if f.get("crack_status") != "none" else None),
        ("Analisado em", f.get("analyzed_at")),
    ], mono=("Caminho completo", "Arquivo físico", "Caminho dentro do compactado", "SHA-256", "Pasta de origem"))
    info = f.get("threat_info") if show_threat_info else None
    info_html = ""
    if info:
        info_html = _rows([("O que pode fazer", info["can_do"]), ("Informações em risco", info["data_at_risk"]),
                           ("Como foi detectado", info["detection"]), ("Limitações da detecção", info["limitations"])])
    fp = ""
    if f.get("possible_false_positive"):
        fp = "<p class='fp'>Falso positivo possível: " + _e(" ".join(f.get("fp_notes") or [
            "as evidências também ocorrem em software legítimo."])) + "</p>"
    return (
        f"<div class='card {RISK_CLASS.get(f['risk'], 'info')}'>"
        f"<h3>{_badge(f['risk'], f['risk_label'])} {_e(f['name'])}<span class='muted'>{_e(member)}</span></h3>"
        f"<div class='muted'>{_e(f.get('risk_meaning'))}</div>{rows}{info_html}"
        + ("<b>Como o nível de risco foi definido</b>" + _list(f["explanation"]) if f.get("explanation") else "")
        + "".join(_evidence(ev) for ev in f.get("evidences") or [])
        + fp
        + ("<b>Ações recomendadas</b>" + _list(f["recommendations"]) if f.get("recommendations") else "")
        + "</div>"
    )


def _crack_card(c: dict) -> str:
    return (
        f"<div class='card {RISK_CLASS.get(c['risk'], 'info')}'>"
        f"<h3>{_badge(c['risk'], c['crack_status_label'])} {_e(c['name'])}</h3>"
        + _rows([
            ("Localização", c["path"]), ("SHA-256", c.get("sha256")),
            ("Tipo de modificação", "; ".join(c.get("modification_types") or [])),
            ("Assinatura digital", (f"válida — {c['signer']}" if c.get("signature_valid") else
                                    "presente, inválida" if c.get("signed") else "ausente")),
            ("Evidências de ameaça", c.get("threat_evidence_count")),
            ("Riscos potenciais", ", ".join(c.get("potential_risks") or []) or "nenhum identificado"),
            ("Falso positivo possível", "sim" if c.get("possible_false_positive") else "não indicado"),
            ("Recomendação de segurança", c.get("crack_recommendation")),
        ], mono=("Localização", "SHA-256"))
        + "".join(_evidence(ev) for ev in c.get("evidences") or [])
        + "</div>"
    )


def _section(num: int, title: str, body: str, anchor: str) -> str:
    return f"<section id='{anchor}'><h2>{num}. {_e(title)}</h2>{body}</section>"


def render_html(r: dict[str, Any]) -> str:
    scan, counts, comp = r["scan"], r["counts"], r["computer"]
    tiles = "".join(
        f"<div class='tile'><b>{_e(v)}</b><span>{_e(k)}</span></div>" for k, v in (
            ("Arquivos encontrados", counts["files_found"]), ("Examinados", counts["files_analyzed"]),
            ("Ameaças", counts["threats"]), ("Suspeitos", counts["suspicious"]), ("PUA", counts["pua"]),
            ("Não examinados", counts["not_examined"]), ("Falsos positivos possíveis", counts["possible_false_positives"]),
            ("Cracks", counts["cracks"]),
        ))
    os_info = comp.get("os", {})
    computer = _rows([
        ("Sistema operacional", f"{os_info.get('product', '')} {os_info.get('edition') or ''} (versão {os_info.get('version')})"),
        ("Observação de suporte", os_info.get("support_note")),
        ("Arquitetura", comp.get("architecture")),
        ("Processador", f"{comp['cpu']['model']} — {comp['cpu']['logical_cores']} núcleos lógicos"),
        ("Memória total", _size(comp.get("memory_total_bytes"))),
        ("Nome do computador", comp.get("hostname")),
        ("Aplicativo", f"{comp['application']['name']} {comp['application']['version']}"),
    ])
    sig = r.get("signatures") or {}
    engines = "".join(
        f"<tr><td>{_e(e.get('name'))}</td><td>{'disponível' if e.get('available') else 'indisponível'}"
        f"{'' if e.get('enabled', True) else ' (desativado)'}</td><td>{_e(e.get('version'))}</td>"
        f"<td>{_e(e.get('detail'))}</td></tr>" for e in r.get("engines") or [])
    engines_html = (f"<table><tr><th>Mecanismo</th><th>Estado</th><th>Versão</th><th>Detalhe</th></tr>{engines}</table>"
                    if engines else "<p class='muted'>Estado dos mecanismos não registrado nesta varredura.</p>")
    sig_html = _rows([
        ("Assinaturas ClamAV", sig.get("clamav_signature_count")), ("Regras YARA", sig.get("yara_rule_count")),
        ("Indicadores locais (IOC)", sig.get("ioc_count")), ("Assinaturas desatualizadas", (
            "sim — " + (sig.get("stale_reason") or "") if sig.get("stale") else "não") if sig else None),
    ])
    not_examined = "".join(
        f"<tr><td><code>{_e(n['path'])}</code></td><td>{_e(n['status_label'])}</td>"
        f"<td>{_e('; '.join(n.get('reasons') or []) or '—')}</td></tr>" for n in r["not_examined"])
    targets = _list(scan["targets"])
    by_class = ", ".join(f"{v['label']}: {v['count']}" for v in counts["by_classification"].values())
    clean = ""
    if r.get("clean_files"):
        clean = "<table>" + "".join(f"<tr><td><code>{_e(c['path'])}</code></td><td><code>{_e(c['sha256'])}</code></td></tr>"
                                    for c in r["clean_files"]) + "</table>"
    scale = "".join(f"<tr><td>{_badge(s['level'], s['label'])}</td><td>{_e(s['meaning'])}</td></tr>" for s in r["risk_scale"])

    body = "".join([
        _section(1, "Informações gerais do computador", computer, "computador"),
        _section(2, "Pasta(s) analisada(s)", targets + _rows([("Modo", scan["mode_label"]), ("Rótulo", scan["label"]),
                                                              ("Origem", scan["origin"])]), "alvo"),
        _section(3, "Data e duração da análise", _rows([
            ("Início", scan["started_at"]), ("Término", scan["finished_at"]),
            ("Duração", f"{scan['duration_seconds']} s"), ("Estado", scan["status_label"]), ("Erro", scan.get("error")),
        ]), "data"),
        _section(4, "Arquivos encontrados", f"<div class='grid'>{tiles}</div>" + _rows([
            ("Arquivos encontrados", counts["files_found"]), ("Membros de compactados analisados", counts["members_analyzed"]),
            ("Bytes verificados", _size(counts["bytes_scanned"])), ("Por classificação", by_class),
        ]), "encontrados"),
        _section(5, "Arquivos examinados", _rows([("Examinados", counts["files_analyzed"]),
                                                  ("Sem indicadores de risco", counts["clean"])]) + clean, "examinados"),
        _section(6, "Arquivos não examinados",
                 (f"<table><tr><th>Arquivo</th><th>Estado</th><th>Motivo</th></tr>{not_examined}</table>"
                  if not_examined else "<p class='muted'>Todos os arquivos selecionados foram examinados.</p>"), "nao-examinados"),
        _section(7, "Ameaças detectadas",
                 "".join(_file_card(f) for f in r["threats"]) or "<p class='muted'>Nenhuma ameaça detectada.</p>", "ameacas"),
        _section(8, "Arquivos suspeitos e potencialmente indesejados",
                 "".join(_file_card(f) for f in r["suspicious"] + r["pua"]) or
                 "<p class='muted'>Nenhum arquivo suspeito.</p>", "suspeitos"),
        _section(9, "Outras evidências técnicas (risco baixo, informativo, modificado ou inconclusivo)",
                 "".join(_file_card(f, show_threat_info=False) for f in r["other_findings"]) or
                 "<p class='muted'>Nenhuma outra ocorrência.</p>", "evidencias"),
        _section(10, "Relatório individual de cracks",
                 "".join(_crack_card(c) for c in r["cracks"]) or "<p class='muted'>Nenhum componente de crack identificado.</p>",
                 "cracks"),
        _section(11, "Classificação de risco: escala e fontes de evidência",
                 f"<table>{scale}</table><p class='muted'>Fontes: "
                 + _e(", ".join(s["label"] for s in r["evidence_sources"])) + ". Os níveis são qualitativos; "
                 "não representam probabilidade de infecção.</p>", "escala"),
        _section(12, "Mecanismos e assinaturas", engines_html + sig_html, "mecanismos"),
        _section(13, "Recomendações", _list(r["recommendations"]), "recomendacoes"),
        _section(14, "Limitações da análise", _list(r["limitations"]) + _list(r.get("warnings") or []), "limitacoes"),
    ])
    max_risk = r["max_risk"]
    return (
        "<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>Relatório Game Kernel — varredura {_e(scan['id'])}</title><style>{CSS}</style></head><body><main>"
        f"<header class='top'><h1>Relatório forense — Game Kernel</h1>"
        f"<div class='muted'>Varredura nº {_e(scan['id'])} · gerado em {_e(r['generated_at'])} · "
        f"{_e(r['generator']['application'])} {_e(r['generator']['version'])}</div>"
        f"<p>Risco máximo: {_badge(max_risk['level'], max_risk['label'])} {_e(max_risk['meaning'])}</p></header>"
        f"{body}<footer>{_e(r['privacy']['note'])} Nome de usuário "
        f"{'omitido' if r['privacy']['username_redacted'] else 'incluído'} nos caminhos.</footer></main></body></html>"
    )
