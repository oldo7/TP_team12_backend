"""
PDF report generator for TARA projects.
Self-contained: does not import from views.py or serializers.py.
"""
import io
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
    Image,
)

from .models import (
    Project, Component, DataEntity, DamageScenario,
    ThreatScenario, AttackStep, Control, ControlGroup,
    RiskTreatment, CybersecurityGoal,
)
from .calculations import (
    calculate_impact_level,
    calculate_risk_level,
    calculate_attack_feasibility,
    best_attack_feasibility_for_threat_scenario,
    best_effective_attack_feasibility_for_threat_scenario,
    RISK_LEVEL_MATRIX,
    _find_all_paths,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAGE_W, PAGE_H = A4
MARGIN    = 15 * mm
CONTENT_W = PAGE_W - 2 * MARGIN   # 180 mm

HDR_BG  = colors.HexColor('#1F3864')
HDR_FG  = colors.white
ALT_ROW = colors.HexColor('#DCE6F1')
BORDER  = colors.HexColor('#B8CCE4')

RL_COLORS = {
    None: colors.white,
    0:    colors.white,
    1:    colors.HexColor('#92D050'),
    2:    colors.HexColor('#FFFF00'),
    3:    colors.HexColor('#FFC000'),
    4:    colors.HexColor('#FF0000'),
    5:    colors.HexColor('#C00000'),
}
IL_COLORS = {
    0: colors.HexColor('#92D050'),
    1: colors.HexColor('#FFFF00'),
    2: colors.HexColor('#FFC000'),
    3: colors.HexColor('#FF0000'),
}
IL_LABELS  = {0: 'Negligible', 1: 'Moderate', 2: 'Major', 3: 'Severe'}
AFL_LABELS = {1: 'Very Low', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Very High'}

ET_MAP  = {0: '<=1d', 1: '<=1w', 4: '<=1m', 10: '<=3m', 17: '<=6m', 19: '>6m', 99: 'NP'}
SE_MAP  = {0: 'Layman', 3: 'Proficient', 6: 'Expert', 8: 'Multi-Exp'}
KOC_MAP = {0: 'Public', 3: 'Restricted', 7: 'Sensitive', 11: 'Critical'}
WOO_MAP = {0: 'Unlimited', 1: 'Easy', 4: 'Moderate', 10: 'Difficult', 99: 'None'}
EQ_MAP  = {0: 'Standard', 4: 'Specialized', 7: 'Bespoke', 9: 'Multi-Bsp'}

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

S_NORMAL = ParagraphStyle('rN', fontName='Helvetica',      fontSize=8,  leading=10)
S_HDR    = ParagraphStyle('rH', fontName='Helvetica-Bold', fontSize=8,  leading=10, textColor=HDR_FG)
S_CENTER = ParagraphStyle('rC', fontName='Helvetica',      fontSize=8,  leading=10, alignment=TA_CENTER)
S_H1     = ParagraphStyle('h1', fontName='Helvetica-Bold', fontSize=15, leading=20, spaceAfter=8)
S_H2     = ParagraphStyle('h2', fontName='Helvetica-Bold', fontSize=11, leading=14, spaceBefore=12, spaceAfter=4)

# ---------------------------------------------------------------------------
# Cell helpers
# ---------------------------------------------------------------------------

def H(text):
    return Paragraph(str(text), S_HDR)

def N(text):
    return Paragraph(str(text), S_NORMAL)

def C(text):
    return Paragraph(str(text), S_CENTER)

def _cia(bitmask):
    parts = []
    if bitmask & 4: parts.append('C')
    if bitmask & 2: parts.append('I')
    if bitmask & 1: parts.append('A')
    return ', '.join(parts) or '-'

# ---------------------------------------------------------------------------
# Table builder
# ---------------------------------------------------------------------------

def _tbl(data, col_widths, extra_cmds=None):
    cmds = [
        ('FONTSIZE',      (0, 0), (-1, -1), 8),
        ('GRID',          (0, 0), (-1, -1), 0.3, BORDER),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
        ('BACKGROUND',    (0, 0), (-1, 0), HDR_BG),
        ('TEXTCOLOR',     (0, 0), (-1, 0), HDR_FG),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            cmds.append(('BACKGROUND', (0, i), (-1, i), ALT_ROW))
    if extra_cmds:
        cmds.extend(extra_cmds)
    return Table(data, colWidths=col_widths, style=TableStyle(cmds),
                 repeatRows=1, hAlign='LEFT')

# ---------------------------------------------------------------------------
# Page template with footer
# ---------------------------------------------------------------------------

def _make_doc(buffer, project_name):
    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(colors.HexColor('#555555'))
        canvas.drawRightString(
            PAGE_W - MARGIN, MARGIN / 2,
            f'{project_name}  |  Page {doc.page}',
        )
        canvas.restoreState()

    doc = BaseDocTemplate(
        buffer, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=MARGIN + 6,
    )
    frame = Frame(MARGIN, MARGIN + 6, CONTENT_W, PAGE_H - 2 * MARGIN - 6, id='main')
    doc.addPageTemplates([PageTemplate(id='main', frames=[frame], onPage=_footer)])
    return doc

# ---------------------------------------------------------------------------
# Risk distribution chart
# ---------------------------------------------------------------------------

def _risk_chart(risk_rows):
    rl_hex = {1: '#92D050', 2: '#FFFF00', 3: '#FFC000', 4: '#FF0000', 5: '#C00000'}

    fig, ax = plt.subplots(figsize=(6.5, 4))

    for il in range(4):
        for afl in range(1, 6):
            rl = RISK_LEVEL_MATRIX.get(il, {}).get(afl, 1)
            ax.add_patch(plt.Rectangle(
                (afl - 0.5, il - 0.5), 1, 1,
                facecolor=rl_hex.get(rl, '#ffffff'),
                edgecolor='#aaaaaa', linewidth=0.5, alpha=0.55,
            ))

    cell_counts = defaultdict(int)
    cell_rl     = defaultdict(int)
    for row in risk_rows:
        if row['il'] is not None and row['afl_value'] is not None:
            k = (row['afl_value'], row['il'])
            cell_counts[k] += 1
            cell_rl[k] = max(cell_rl[k], row['rl'] or 0)

    for (afl, il), count in cell_counts.items():
        rl = cell_rl[(afl, il)] or 1
        radius = 0.15 + 0.12 * (count ** 0.5)
        ax.add_patch(plt.Circle(
            (afl, il), radius,
            color=rl_hex.get(rl, '#888888'), ec='#333333', linewidth=0.8, zorder=5,
        ))
        ax.text(afl, il, str(count), ha='center', va='center',
                fontsize=8, fontweight='bold', zorder=6)

    ax.set_xlim(0.5, 5.5)
    ax.set_ylim(-0.5, 3.5)
    ax.set_xticks(range(1, 6))
    ax.set_xticklabels(['Very Low', 'Low', 'Medium', 'High', 'Very High'], fontsize=7)
    ax.set_yticks(range(4))
    ax.set_yticklabels(['Negligible', 'Moderate', 'Major', 'Severe'], fontsize=7)
    ax.set_xlabel('Attack Feasibility', fontsize=8)
    ax.set_ylabel('Impact', fontsize=8)
    ax.set_title('Risk Distribution', fontsize=10, fontweight='bold')
    ax.legend(
        handles=[mpatches.Patch(color=rl_hex[i], label=f'RL {i}') for i in range(1, 6)],
        loc='lower right', fontsize=6, title='Risk Level', title_fontsize=6,
    )
    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=120, bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return Image(buf, width=130 * mm, height=85 * mm)

# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_project_info(project):
    rows = [
        [H('Field'),       H('Value')],
        [N('Project'),     N(project.name)],
        [N('Description'), N(project.description or '—')],
        [N('Owner'),       N(project.owner.username)],
        [N('Created'),     N(project.created_at.strftime('%Y-%m-%d'))],
    ]
    return [
        Paragraph('Project Information', S_H2),
        _tbl(rows, [55 * mm, CONTENT_W - 55 * mm]),
        Spacer(1, 6 * mm),
    ]


def _section_data_entities(data_entities, damage_scenarios):
    # Map component_id → list of DS names (via concerns)
    comp_to_ds = defaultdict(list)
    for ds in damage_scenarios:
        for concern in ds.concerns.all():
            comp_to_ds[concern.component_id].append(ds.name)

    rows = [[H('ID'), H('Name'), H('Component'), H('Damage Scenarios')]]
    for idx, de in enumerate(data_entities, 1):
        comp_name = de.component.name if de.component else '—'
        ds_names  = list(dict.fromkeys(comp_to_ds.get(de.component_id, [])))
        rows.append([
            N(f'D.{idx}'), N(de.name), N(comp_name),
            N(', '.join(ds_names) if ds_names else '—'),
        ])

    w    = [12*mm, 38*mm, 38*mm, CONTENT_W - 88*mm]
    body = _tbl(rows, w) if len(rows) > 1 else Paragraph('No data entities.', S_NORMAL)
    return [Paragraph('Assets – Data Entities', S_H2), body, Spacer(1, 6*mm)]


def _section_components(components, damage_scenarios):
    comp_to_entries = defaultdict(list)
    for ds in damage_scenarios:
        for concern in ds.concerns.all():
            comp_to_entries[concern.component_id].append((ds.name, concern.affected_CIA_parts))

    rows = [[H('ID'), H('Component'), H('C'), H('I'), H('A'), H('Damage Scenarios')]]
    for idx, comp in enumerate(components, 1):
        entries     = comp_to_entries.get(comp.id, [])
        cia_union   = 0
        for _, cia in entries:
            cia_union |= cia
        ds_names = list(dict.fromkeys(name for name, _ in entries))
        rows.append([
            N(f'C.{idx}'), N(comp.name),
            C('X' if cia_union & 4 else '-'),
            C('X' if cia_union & 2 else '-'),
            C('X' if cia_union & 1 else '-'),
            N(', '.join(ds_names) if ds_names else '—'),
        ])

    w    = [10*mm, 38*mm, 8*mm, 8*mm, 8*mm, CONTENT_W - 72*mm]
    body = _tbl(rows, w) if len(rows) > 1 else Paragraph('No components.', S_NORMAL)
    return [Paragraph('Assets – Components', S_H2), body, Spacer(1, 6*mm)]


def _section_damage_overview(damage_scenarios):
    rows  = [[H('ID'), H('Name'), H('Concerns (Component: CIA)'), H('IS'), H('IL'), H('S'), H('F'), H('O'), H('P')]]
    extra = []
    for idx, ds in enumerate(damage_scenarios, 1):
        il = calculate_impact_level(ds)
        concern_strs = [
            f'{c.component.name}: {_cia(c.affected_CIA_parts)}'
            for c in ds.concerns.all()
        ] or [_cia(ds.affected_CIA_parts)]
        row_i = len(rows)   # 0-based index of the row about to be appended
        extra.append(('BACKGROUND', (4, row_i), (4, row_i), IL_COLORS.get(il, colors.white)))
        rows.append([
            N(f'DS.{idx}'), N(ds.name), N('; '.join(concern_strs)),
            C(str(il)), C(IL_LABELS.get(il, str(il))),
            C(str(ds.safety_impact)), C(str(ds.finantial_impact)),
            C(str(ds.operational_impact)), C(str(ds.privacy_impact)),
        ])

    w    = [12*mm, 35*mm, 55*mm, 8*mm, 22*mm, 12*mm, 12*mm, 12*mm, 12*mm]
    body = _tbl(rows, w, extra_cmds=extra) if len(rows) > 1 else Paragraph('No damage scenarios.', S_NORMAL)
    return [Paragraph('Damage Scenarios Overview', S_H2), body, Spacer(1, 6*mm)]


def _section_ds_ts_crossref(damage_scenarios, threat_scenarios):
    ts_index = {ts.id: idx for idx, ts in enumerate(threat_scenarios, 1)}
    rows = [[H('DS ID'), H('Damage Scenario'), H('TS ID'), H('Threat Scenario')]]
    for idx, ds in enumerate(damage_scenarios, 1):
        linked = list(ds.threat_scenarios.all())
        if not linked:
            rows.append([N(f'DS.{idx}'), N(ds.name), C('—'), N('—')])
            continue
        for ts in linked:
            ts_idx = ts_index.get(ts.id, '?')
            rows.append([N(f'DS.{idx}'), N(ds.name), C(f'TS.{ts_idx}'), N(ts.name)])

    w    = [12*mm, 70*mm, 12*mm, CONTENT_W - 94*mm]
    body = _tbl(rows, w) if len(rows) > 1 else Paragraph('No cross-references.', S_NORMAL)
    return [Paragraph('Damage – Threat Scenarios Cross-Reference', S_H2), body, Spacer(1, 6*mm)]


def _section_threat_paths(threat_scenarios):
    rows  = [[H('ID'), H('Threat Scenario'), H('Path'), H('Attack Steps'), H('AFL')]]
    extra = []
    for ts_idx, ts in enumerate(threat_scenarios, 1):
        steps = list(ts.attack_steps.all())
        paths = _find_all_paths(steps)
        afl   = best_attack_feasibility_for_threat_scenario(ts)
        afl_label = afl.get('afl') or '—'
        afl_val   = afl.get('afl_value')
        afl_color = RL_COLORS.get(afl_val)

        if not paths:
            rows.append([N(f'TS.{ts_idx}'), N(ts.name), C('—'), N('—'), C(afl_label)])
            continue

        for p_idx, path in enumerate(paths, 1):
            row_i      = len(rows)
            step_names = ' -> '.join(s.name for s in path)
            is_first   = (p_idx == 1)
            rows.append([
                N(f'TS.{ts_idx}') if is_first else N(''),
                N(ts.name)        if is_first else N(''),
                C(f'AP{p_idx}'),
                N(step_names),
                C(afl_label)      if is_first else N(''),
            ])
            if is_first and afl_color:
                extra.append(('BACKGROUND', (4, row_i), (4, row_i), afl_color))

    w    = [12*mm, 45*mm, 12*mm, 85*mm, 26*mm]
    body = _tbl(rows, w, extra_cmds=extra) if len(rows) > 1 else Paragraph('No threat scenarios.', S_NORMAL)
    return [Paragraph('Threat Scenarios and Attack Paths', S_H2), body, Spacer(1, 6*mm)]


def _section_attack_steps(attack_steps):
    rows  = [[H('ID'), H('Name'), H('Component'), H('ET'), H('SE'), H('KoC'), H('WoO'), H('Eq'), H('AFL')]]
    extra = []
    for idx, s in enumerate(attack_steps, 1):
        afl   = calculate_attack_feasibility(s)
        afl_v = afl.get('afl_value')
        row_i = len(rows)
        if afl_v and afl_v in RL_COLORS:
            extra.append(('BACKGROUND', (8, row_i), (8, row_i), RL_COLORS[afl_v]))
        rows.append([
            N(f'AS.{idx}'), N(s.name),
            N(s.component.name if s.component else '—'),
            N(ET_MAP.get(s.fr_et, str(s.fr_et))),
            N(SE_MAP.get(s.fr_se, str(s.fr_se))),
            N(KOC_MAP.get(s.fr_koC, str(s.fr_koC))),
            N(WOO_MAP.get(s.fr_WoO, str(s.fr_WoO))),
            N(EQ_MAP.get(s.fr_eq, str(s.fr_eq))),
            C(afl.get('afl') or '—'),
        ])

    w    = [10*mm, 38*mm, 25*mm, 14*mm, 18*mm, 18*mm, 18*mm, 18*mm, 21*mm]
    body = _tbl(rows, w, extra_cmds=extra) if len(rows) > 1 else Paragraph('No attack steps.', S_NORMAL)
    return [Paragraph('Attack Steps Table', S_H2), body, Spacer(1, 6*mm)]


def _section_controls(controls):
    rows  = [[H('ID'), H('Name'), H('Component'), H('ET'), H('SE'), H('KoC'), H('WoO'), H('Eq'), H('AFL')]]
    extra = []
    for idx, c in enumerate(controls, 1):
        afl   = calculate_attack_feasibility(c)
        afl_v = afl.get('afl_value')
        row_i = len(rows)
        if afl_v and afl_v in RL_COLORS:
            extra.append(('BACKGROUND', (8, row_i), (8, row_i), RL_COLORS[afl_v]))
        rows.append([
            N(f'C.{idx}'), N(c.name),
            N(c.component.name if c.component else '—'),
            N(ET_MAP.get(c.fr_et, str(c.fr_et))),
            N(SE_MAP.get(c.fr_se, str(c.fr_se))),
            N(KOC_MAP.get(c.fr_koC, str(c.fr_koC))),
            N(WOO_MAP.get(c.fr_WoO, str(c.fr_WoO))),
            N(EQ_MAP.get(c.fr_eq, str(c.fr_eq))),
            C(afl.get('afl') or '—'),
        ])

    w    = [10*mm, 38*mm, 25*mm, 14*mm, 18*mm, 18*mm, 18*mm, 18*mm, 21*mm]
    body = _tbl(rows, w, extra_cmds=extra) if len(rows) > 1 else Paragraph('No controls.', S_NORMAL)
    return [Paragraph('Controls Table (Accumulated)', S_H2), body, Spacer(1, 6*mm)]


def _section_risks(risk_rows):
    rows  = [[H('ID'), H('Threat Scenario'), H('Damage Scenario'), H('AFL'), H('IL'), H('RL')]]
    extra = []
    for row in risk_rows:
        il    = row['il']
        rl    = row['rl']
        row_i = len(rows)
        if il is not None:
            extra.append(('BACKGROUND', (4, row_i), (4, row_i), IL_COLORS.get(il, colors.white)))
        if rl is not None:
            extra.append(('BACKGROUND', (5, row_i), (5, row_i), RL_COLORS.get(rl, colors.white)))
        rows.append([
            N(f'R.{row["idx"]}'),
            N(row['ts'].name),
            N(row['ds'].name),
            C(row['afl'].get('afl') or '—'),
            C(IL_LABELS.get(il, '—')),
            C(str(rl) if rl is not None else '—'),
        ])

    w    = [12*mm, 60*mm, 60*mm, 20*mm, 16*mm, 12*mm]
    body = _tbl(rows, w, extra_cmds=extra) if len(rows) > 1 else Paragraph('No risks.', S_NORMAL)
    return [Paragraph('Risks Table', S_H2), body, Spacer(1, 6*mm)]


def _section_control_scenarios(risk_rows, control_groups):
    groups = list(control_groups)
    if not groups:
        return [
            Paragraph('Control Scenarios per Risk', S_H2),
            Paragraph('No control groups defined.', S_NORMAL),
            Spacer(1, 6*mm),
        ]

    # Columns: ID | Risk name | No Controls (baseline) | one col per group
    n_data_cols = 1 + len(groups)   # baseline + one per group
    fixed_w     = [12*mm, 55*mm]
    remaining   = CONTENT_W - sum(fixed_w)
    col_w       = min(remaining / n_data_cols, 28*mm)
    col_widths  = fixed_w + [col_w] * n_data_cols

    header = [H('ID'), H('Risk'), H('No Controls')] + [H(g.name[:14]) for g in groups]
    rows   = [header]
    extra  = []

    for row in risk_rows:
        il  = row['il']
        ts  = row['ts']
        ds  = row['ds']
        # Baseline RL (no controls active)
        base_rl  = row['rl']
        data_row = [N(f'R.{row["idx"]}'), N(f'{ts.name} / {ds.name}'), C(str(base_rl) if base_rl is not None else '—')]
        r_i = len(rows)
        if base_rl is not None:
            extra.append(('BACKGROUND', (2, r_i), (2, r_i), RL_COLORS.get(base_rl, colors.white)))

        for g_idx, group in enumerate(groups):
            active = list(group.controls.all())
            eff    = best_effective_attack_feasibility_for_threat_scenario(ts, active)
            rl     = calculate_risk_level(il, eff.get('afl_value'))
            data_row.append(C(str(rl) if rl is not None else '—'))
            col_i = 3 + g_idx
            if rl is not None:
                extra.append(('BACKGROUND', (col_i, r_i), (col_i, r_i), RL_COLORS.get(rl, colors.white)))

        rows.append(data_row)

    body = _tbl(rows, col_widths, extra_cmds=extra)
    return [Paragraph('Control Scenarios per Risk', S_H2), body, Spacer(1, 6*mm)]


def _section_risk_treatment(risk_rows):
    rows  = [[H('ID'), H('Risk'), H('RL'), H('Treatment'), H('Rationale')]]
    extra = []
    for row in risk_rows:
        if not row['treatment']:
            continue
        rl    = row['rl']
        t     = row['treatment']
        row_i = len(rows)
        if rl is not None:
            extra.append(('BACKGROUND', (2, row_i), (2, row_i), RL_COLORS.get(rl, colors.white)))
        rows.append([
            N(f'R.{row["idx"]}'),
            N(f'{row["ts"].name} / {row["ds"].name}'),
            C(str(rl) if rl is not None else '—'),
            N(t.decision.capitalize()),
            N(t.rationale or '—'),
        ])

    if len(rows) == 1:
        body = Paragraph('No risk treatments recorded.', S_NORMAL)
    else:
        w    = [12*mm, 65*mm, 12*mm, 20*mm, CONTENT_W - 109*mm]
        body = _tbl(rows, w, extra_cmds=extra)
    return [Paragraph('Risk Treatment Table', S_H2), body, Spacer(1, 6*mm)]


def _section_cybersecurity_goals(goals):
    CAL = {1: 'CAL 1', 2: 'CAL 2', 3: 'CAL 3', 4: 'CAL 4'}
    rows = [[H('ID'), H('Name'), H('CAL'), H('Damage Scenarios'), H('Controls')]]
    for idx, g in enumerate(goals, 1):
        ds_names   = ', '.join(ds.name for ds in g.damage_scenarios.all()) or '—'
        ctrl_names = ', '.join(c.name for c in g.controls.all()) or '—'
        rows.append([
            N(f'CG.{idx}'), N(g.name),
            C(CAL.get(g.cal, '—') if g.cal else '—'),
            N(ds_names), N(ctrl_names),
        ])

    w    = [12*mm, 40*mm, 15*mm, 56*mm, CONTENT_W - 123*mm]
    body = _tbl(rows, w) if len(rows) > 1 else Paragraph('No cybersecurity goals.', S_NORMAL)
    return [Paragraph('Cybersecurity Goals', S_H2), body, Spacer(1, 6*mm)]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_report_pdf(project: Project) -> bytes:
    """Generate a PDF TARA report and return it as bytes."""

    # Fetch all data with appropriate prefetches
    threat_scenarios = list(
        ThreatScenario.objects
        .filter(project=project)
        .prefetch_related(
            'attack_steps',
            'attack_steps__previous_steps',
            'attack_steps__controls',
            'damage_scenarios',
            'damage_scenarios__concerns',
            'damage_scenarios__concerns__component',
        )
    )
    damage_scenarios = list(
        DamageScenario.objects
        .filter(project=project)
        .prefetch_related('concerns', 'concerns__component', 'threat_scenarios')
    )
    components = list(
        Component.objects
        .filter(project=project)
        .prefetch_related('damage_scenario_concerns', 'damage_scenario_concerns__damage_scenario')
    )
    data_entities = list(
        DataEntity.objects
        .filter(project=project)
        .select_related('component')
    )
    attack_steps = list(
        AttackStep.objects
        .filter(project=project)
        .select_related('component')
    )
    controls = list(
        Control.objects
        .filter(project=project)
        .select_related('component')
    )
    control_groups = list(
        ControlGroup.objects
        .filter(project=project)
        .prefetch_related('controls', 'controls__attack_steps')
    )
    treatments = {
        (t.threat_scenario_id, t.damage_scenario_id): t
        for t in RiskTreatment.objects.filter(project=project)
    }
    goals = list(
        CybersecurityGoal.objects
        .filter(project=project)
        .prefetch_related('damage_scenarios', 'controls')
    )

    # Build unique (TS x DS) risk rows
    risk_rows = []
    seen = set()
    for ts in threat_scenarios:
        afl = best_attack_feasibility_for_threat_scenario(ts)
        for ds in ts.damage_scenarios.all():
            key = (ts.id, ds.id)
            if key in seen:
                continue
            seen.add(key)
            il  = calculate_impact_level(ds)
            rl  = calculate_risk_level(il, afl.get('afl_value'))
            risk_rows.append({
                'idx':       len(risk_rows) + 1,
                'ts':        ts,
                'ds':        ds,
                'il':        il,
                'rl':        rl,
                'afl':       afl,
                'afl_value': afl.get('afl_value'),
                'treatment': treatments.get(key),
            })

    # Assemble the document
    buffer = io.BytesIO()
    doc    = _make_doc(buffer, project.name)

    story = [
        Paragraph(f'TARA Report: {project.name}', S_H1),
        Spacer(1, 4 * mm),
    ]
    story += _section_project_info(project)
    story += [Paragraph('Risk Distribution Chart', S_H2), _risk_chart(risk_rows), Spacer(1, 6*mm)]
    story += _section_data_entities(data_entities, damage_scenarios)
    story += _section_components(components, damage_scenarios)
    story += _section_damage_overview(damage_scenarios)
    story += _section_ds_ts_crossref(damage_scenarios, threat_scenarios)
    story += _section_threat_paths(threat_scenarios)
    story += _section_attack_steps(attack_steps)
    story += _section_controls(controls)
    story += _section_risks(risk_rows)
    story += _section_control_scenarios(risk_rows, control_groups)
    story += _section_risk_treatment(risk_rows)
    story += _section_cybersecurity_goals(goals)

    doc.build(story)
    return buffer.getvalue()
