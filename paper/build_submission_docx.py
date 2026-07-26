"""Build the verified Crime and Policy manuscript as a journal-formatted DOCX.

The output follows the geometry published in the Korean Society of Criminology's
editorial rules: 208 x 277 mm, portrait; top 20 mm; bottom/left/right 15 mm;
header/footer 15 mm. It intentionally remains a review copy because author
identity, KCI similarity results, and the society's HWP template are external.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from docx import Document
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Mm, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "paper" / "범죄와정책_최종논문_검증반영.md"
OUTPUT = ROOT / "paper" / "범죄와정책_투고원고_검증본.docx"

BODY_FONT = "바탕"
HEADING_FONT = "맑은 고딕"
MONO_FONT = "Consolas"
BLACK = RGBColor(0, 0, 0)
MUTED = RGBColor(90, 90, 90)
HEADER_FILL = "E7E7E7"
CONTENT_WIDTH_DXA = 9970
TABLE_INDENT_DXA = 120


def set_font(run, name=BODY_FONT, size=9.6, bold=None, italic=None, color=BLACK):
    run.font.name = name
    run.font.size = Pt(size)
    run.font.color.rgb = color
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.insert(0, rfonts)
    for attr in ("ascii", "hAnsi", "eastAsia"):
        rfonts.set(qn(f"w:{attr}"), name)


def set_style_font(style, name, size, bold=False):
    style.font.name = name
    style.font.size = Pt(size)
    style.font.bold = bold
    style.font.color.rgb = BLACK
    rpr = style.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.insert(0, rfonts)
    for attr in ("ascii", "hAnsi", "eastAsia"):
        rfonts.set(qn(f"w:{attr}"), name)


def set_cell_margins(cell, top=70, start=100, bottom=70, end=100):
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for side, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tc_mar.find(qn(f"w:{side}"))
        if node is None:
            node = OxmlElement(f"w:{side}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_repeat_table_header(row):
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def prevent_row_split(row):
    tr_pr = row._tr.get_or_add_trPr()
    cant_split = OxmlElement("w:cantSplit")
    tr_pr.append(cant_split)


def shade_cell(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def set_table_borders(table):
    tbl_pr = table._tbl.tblPr
    borders = tbl_pr.find(qn("w:tblBorders"))
    if borders is None:
        borders = OxmlElement("w:tblBorders")
        tbl_pr.append(borders)
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        tag = borders.find(qn(f"w:{edge}"))
        if tag is None:
            tag = OxmlElement(f"w:{edge}")
            borders.append(tag)
        tag.set(qn("w:val"), "single")
        tag.set(qn("w:sz"), "4")
        tag.set(qn("w:space"), "0")
        tag.set(qn("w:color"), "777777")


def display_len(text):
    return sum(2 if ord(ch) > 127 else 1 for ch in text)


def column_widths(headers, rows):
    maxima = []
    for idx, header in enumerate(headers):
        values = [header] + [row[idx] if idx < len(row) else "" for row in rows]
        maxima.append(min(max(display_len(value) for value in values), 42))
    weights = [max(4.0, math.pow(length, 0.65)) for length in maxima]
    minimum = 760 if len(headers) >= 6 else 900 if len(headers) >= 4 else 1100
    available = CONTENT_WIDTH_DXA - minimum * len(headers)
    total_weight = sum(weights)
    widths = [minimum + int(available * weight / total_weight) for weight in weights]
    widths[-1] += CONTENT_WIDTH_DXA - sum(widths)
    return widths


def apply_table_geometry(table, widths):
    table.autofit = False
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    tbl_pr = table._tbl.tblPr

    tbl_w = tbl_pr.find(qn("w:tblW"))
    if tbl_w is None:
        tbl_w = OxmlElement("w:tblW")
        tbl_pr.append(tbl_w)
    tbl_w.set(qn("w:w"), str(sum(widths)))
    tbl_w.set(qn("w:type"), "dxa")

    tbl_ind = tbl_pr.find(qn("w:tblInd"))
    if tbl_ind is None:
        tbl_ind = OxmlElement("w:tblInd")
        tbl_pr.append(tbl_ind)
    tbl_ind.set(qn("w:w"), str(TABLE_INDENT_DXA))
    tbl_ind.set(qn("w:type"), "dxa")

    grid = table._tbl.tblGrid
    for child in list(grid):
        grid.remove(child)
    for width in widths:
        grid_col = OxmlElement("w:gridCol")
        grid_col.set(qn("w:w"), str(width))
        grid.append(grid_col)

    for row in table.rows:
        prevent_row_split(row)
        for idx, cell in enumerate(row.cells):
            tc_pr = cell._tc.get_or_add_tcPr()
            tc_w = tc_pr.find(qn("w:tcW"))
            if tc_w is None:
                tc_w = OxmlElement("w:tcW")
                tc_pr.append(tc_w)
            tc_w.set(qn("w:w"), str(widths[idx]))
            tc_w.set(qn("w:type"), "dxa")
            set_cell_margins(cell)
    set_table_borders(table)


TOKEN_RE = re.compile(r"(\*\*.+?\*\*|(?<!\*)\*[^*]+?\*(?!\*)|`[^`]+`)")


def add_inline(paragraph, text, size=9.6, color=BLACK):
    cursor = 0
    for match in TOKEN_RE.finditer(text):
        if match.start() > cursor:
            set_font(paragraph.add_run(text[cursor : match.start()]), size=size, color=color)
        token = match.group(0)
        if token.startswith("**"):
            set_font(paragraph.add_run(token[2:-2]), size=size, bold=True, color=color)
        elif token.startswith("*"):
            set_font(paragraph.add_run(token[1:-1]), size=size, italic=True, color=color)
        else:
            set_font(paragraph.add_run(token[1:-1]), name=MONO_FONT, size=max(8.2, size - 0.5), color=color)
        cursor = match.end()
    if cursor < len(text):
        set_font(paragraph.add_run(text[cursor:]), size=size, color=color)


def add_body_paragraph(doc, text, style=None, indent=True, size=9.6):
    p = doc.add_paragraph(style=style)
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.line_spacing = 1.38
    p.paragraph_format.widow_control = True
    if indent and style is None:
        p.paragraph_format.first_line_indent = Mm(7)
    add_inline(p, text, size=size)
    return p


def add_heading(doc, text, level):
    p = doc.add_paragraph(style=f"Heading {level}")
    p.paragraph_format.keep_with_next = True
    p.paragraph_format.keep_together = True
    add_inline(p, text, size={1: 12.5, 2: 11.2, 3: 10.3}.get(level, 9.8))
    for run in p.runs:
        set_font(
            run,
            name=HEADING_FONT,
            size={1: 12.5, 2: 11.2, 3: 10.3}.get(level, 9.8),
            bold=True,
        )
    return p


def add_table(doc, headers, rows):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    header = table.rows[0]
    set_repeat_table_header(header)
    font_size = 7.8 if len(headers) >= 6 else 8.3

    for idx, value in enumerate(headers):
        cell = header.cells[idx]
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        shade_cell(cell, HEADER_FILL)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.05
        run = p.add_run(value)
        set_font(run, name=HEADING_FONT, size=font_size, bold=True)

    for row_values in rows:
        cells = table.add_row().cells
        for idx, value in enumerate(row_values):
            cell = cells[idx]
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT if idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.05
            add_inline(p, value, size=font_size)

    apply_table_geometry(table, column_widths(headers, rows))
    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(1)
    return table


def add_page_number(section):
    footer = section.footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    run = p.add_run()
    set_font(run, name=BODY_FONT, size=8.5, color=MUTED)
    fld_begin = OxmlElement("w:fldChar")
    fld_begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = " PAGE "
    fld_separate = OxmlElement("w:fldChar")
    fld_separate.set(qn("w:fldCharType"), "separate")
    text = OxmlElement("w:t")
    text.text = "1"
    fld_end = OxmlElement("w:fldChar")
    fld_end.set(qn("w:fldCharType"), "end")
    for element in (fld_begin, instr, fld_separate, text, fld_end):
        run._r.append(element)


def configure_styles(doc):
    normal = doc.styles["Normal"]
    set_style_font(normal, BODY_FONT, 9.6)
    normal.paragraph_format.space_before = Pt(0)
    normal.paragraph_format.space_after = Pt(3)
    normal.paragraph_format.line_spacing = 1.38

    heading_tokens = {
        1: (12.5, 12, 7),
        2: (11.2, 9, 5),
        3: (10.3, 7, 4),
    }
    for level, (size, before, after) in heading_tokens.items():
        style = doc.styles[f"Heading {level}"]
        set_style_font(style, HEADING_FONT, size, bold=True)
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True
        style.paragraph_format.keep_together = True

    for name in ("List Bullet", "List Number"):
        style = doc.styles[name]
        set_style_font(style, BODY_FONT, 9.6)
        style.paragraph_format.left_indent = Mm(7)
        style.paragraph_format.first_line_indent = Mm(-3.5)
        style.paragraph_format.space_after = Pt(2)
        style.paragraph_format.line_spacing = 1.30

    if "Journal Abstract" not in [s.name for s in doc.styles]:
        abstract = doc.styles.add_style("Journal Abstract", WD_STYLE_TYPE.PARAGRAPH)
    else:
        abstract = doc.styles["Journal Abstract"]
    set_style_font(abstract, BODY_FONT, 9.0)
    abstract.paragraph_format.left_indent = Mm(5)
    abstract.paragraph_format.right_indent = Mm(5)
    abstract.paragraph_format.space_after = Pt(3)
    abstract.paragraph_format.line_spacing = 1.30


def configure_page(doc):
    section = doc.sections[0]
    section.page_width = Mm(208)
    section.page_height = Mm(277)
    section.top_margin = Mm(20)
    section.bottom_margin = Mm(15)
    section.left_margin = Mm(15)
    section.right_margin = Mm(15)
    section.header_distance = Mm(15)
    section.footer_distance = Mm(15)
    add_page_number(section)


def build():
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    doc = Document()
    configure_page(doc)
    configure_styles(doc)

    in_abstract = False
    seen_main_body = False
    title_count = 0
    idx = 0
    while idx < len(lines):
        line = lines[idx].rstrip()

        if not line:
            idx += 1
            continue

        if line == "---":
            if title_count >= 3:
                seen_main_body = True
            idx += 1
            continue

        if line.startswith("|") and idx + 1 < len(lines) and re.match(r"^\|[\-: |]+\|$", lines[idx + 1]):
            headers = [cell.strip() for cell in line.strip("|").split("|")]
            idx += 2
            rows = []
            while idx < len(lines) and lines[idx].startswith("|"):
                rows.append([cell.strip() for cell in lines[idx].strip("|").split("|")])
                idx += 1
            add_table(doc, headers, rows)
            continue

        if line.startswith("# ") and title_count == 0:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(5)
            p.paragraph_format.space_after = Pt(8)
            run = p.add_run(line[2:])
            set_font(run, name=HEADING_FONT, size=18, bold=True)
            title_count += 1
        elif line.startswith("## ") and title_count == 1 and not seen_main_body:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(5)
            add_inline(p, line[3:], size=11.5)
            for run in p.runs:
                set_font(run, name=HEADING_FONT, size=11.5, bold=True)
            title_count += 1
        elif line.startswith("### ") and title_count == 2 and not seen_main_body:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(10)
            text = line[4:].strip("*")
            run = p.add_run(text)
            set_font(run, name=BODY_FONT, size=10.0, italic=True)
            title_count += 1
        elif line.startswith("# "):
            text = line[2:]
            in_abstract = text in ("국문초록", "Abstract")
            add_heading(doc, text, 1)
        elif line.startswith("## "):
            add_heading(doc, line[3:], 2)
        elif line.startswith("### "):
            add_heading(doc, line[4:], 3)
        elif line.startswith("#### "):
            add_heading(doc, line[5:], 3)
        elif line.startswith("- "):
            add_body_paragraph(doc, line[2:], style="List Bullet", indent=False)
        elif re.match(r"^\d+\.\s+", line):
            add_body_paragraph(doc, re.sub(r"^\d+\.\s+", "", line), style="List Number", indent=False)
        elif not seen_main_body and line.startswith("**민우"):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(2)
            add_inline(p, line, size=11)
        elif not seen_main_body:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(2)
            add_inline(p, line, size=8.8, color=MUTED)
        elif in_abstract or line.startswith("**주제어:**") or line.startswith("**Keywords:**"):
            add_body_paragraph(doc, line, style="Journal Abstract", indent=False, size=9.0)
        else:
            add_body_paragraph(doc, line)
        idx += 1

    core = doc.core_properties
    core.title = (
        "생성형 AI의 한국어 개인식별정보(PII) 유출 위험과 "
        "정규화 기반 Layer 0의 필요성"
    )
    core.subject = "「범죄와 정책」 투고 검증본"
    core.keywords = "생성형 인공지능, 개인정보, 가드레일, Layer 0, 형사정책"
    core.author = ""
    core.last_modified_by = ""
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    build()
