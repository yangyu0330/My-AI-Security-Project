"""Build the verified Crime and Policy manuscript as a journal-formatted DOCX.

The output follows the geometry published in the Korean Society of Criminology's
editorial rules: 208 x 277 mm, portrait; top 20 mm; bottom/left/right 15 mm;
header/footer 15 mm. It intentionally remains a review copy because author
identity, KCI similarity results, and the society's accepted final file format
are external.
"""

from __future__ import annotations

import math
import os
import re
import tempfile
import zipfile
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
ANONYMOUS_OUTPUT = ROOT / "paper" / "범죄와정책_심사용_익명원고_최종.docx"

BODY_FONT = "HY신명조"
HEADING_FONT = "HY견고딕"
MONO_FONT = "Consolas"
BLACK = RGBColor(0, 0, 0)
MUTED = RGBColor(90, 90, 90)
HEADER_FILL = "E7E7E7"
CONTENT_WIDTH_DXA = 9970
TABLE_INDENT_DXA = 120


def normalize_docx_archive(path: Path, scrub_metadata: bool = False) -> None:
    """Make the OOXML container byte-reproducible without changing its content."""
    with tempfile.NamedTemporaryFile(
        dir=path.parent,
        prefix=f"{path.stem}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        normalized_path = Path(handle.name)
    try:
        with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(
            normalized_path,
            "w",
        ) as target:
            for source_info in sorted(source.infolist(), key=lambda item: item.filename):
                if scrub_metadata and source_info.filename == "docProps/custom.xml":
                    continue
                target_info = zipfile.ZipInfo(
                    source_info.filename,
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                target_info.compress_type = source_info.compress_type
                target_info.external_attr = source_info.external_attr
                target_info.internal_attr = source_info.internal_attr
                target_info.create_system = 0
                data = source.read(source_info.filename)
                if scrub_metadata and source_info.filename.endswith(".xml"):
                    data = re.sub(rb' w:rsid[A-Za-z0-9]+="[^"]*"', b"", data)
                    if source_info.filename == "docProps/core.xml":
                        data = re.sub(
                            rb"<dc:creator>.*?</dc:creator>",
                            b"<dc:creator></dc:creator>",
                            data,
                        )
                        data = re.sub(
                            rb"<cp:lastModifiedBy>.*?</cp:lastModifiedBy>",
                            b"<cp:lastModifiedBy></cp:lastModifiedBy>",
                            data,
                        )
                        data = re.sub(
                            rb"<dc:description>.*?</dc:description>",
                            b"<dc:description></dc:description>",
                            data,
                        )
                target.writestr(target_info, data)
        os.replace(normalized_path, path)
    finally:
        if normalized_path.exists():
            normalized_path.unlink()


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
        if edge in ("left", "right", "insideV"):
            tag.set(qn("w:val"), "nil")
            tag.set(qn("w:sz"), "0")
        else:
            tag.set(qn("w:val"), "single")
            tag.set(qn("w:sz"), "8" if edge in ("top", "bottom") else "4")
        tag.set(qn("w:space"), "0")
        tag.set(qn("w:color"), "000000")


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


def add_body_paragraph(doc, text, style=None, indent=True, size=10.0):
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


def add_numbered_paragraph(doc, text):
    """Render the source number literally so each independent list can restart."""
    p = add_body_paragraph(doc, text, indent=False)
    p.paragraph_format.left_indent = Mm(7)
    p.paragraph_format.first_line_indent = Mm(-3.5)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.30
    return p


def add_bulleted_paragraph(doc, text):
    """Use a literal bullet to avoid compatibility-mode list reflow defects."""
    p = add_body_paragraph(doc, f"• {text}", indent=False)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.left_indent = Mm(7)
    p.paragraph_format.first_line_indent = Mm(-3.5)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.30
    return p


def add_heading(doc, text, level):
    p = doc.add_paragraph(style=f"Heading {level}")
    p.paragraph_format.keep_with_next = True
    p.paragraph_format.keep_together = True
    add_inline(p, text, size={1: 14.0, 2: 12.0, 3: 11.0}.get(level, 10.0))
    for run in p.runs:
        set_font(
            run,
            name=HEADING_FONT,
            size={1: 14.0, 2: 12.0, 3: 11.0}.get(level, 10.0),
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
    set_style_font(normal, BODY_FONT, 10.0)
    normal.paragraph_format.space_before = Pt(0)
    normal.paragraph_format.space_after = Pt(3)
    normal.paragraph_format.line_spacing = 1.38

    heading_tokens = {
        1: (14.0, 12, 7),
        2: (12.0, 9, 5),
        3: (11.0, 7, 4),
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
        set_style_font(style, BODY_FONT, 10.0)
        style.paragraph_format.left_indent = Mm(7)
        style.paragraph_format.first_line_indent = Mm(-3.5)
        style.paragraph_format.space_after = Pt(2)
        style.paragraph_format.line_spacing = 1.30

    if "Journal Abstract" not in [s.name for s in doc.styles]:
        abstract = doc.styles.add_style("Journal Abstract", WD_STYLE_TYPE.PARAGRAPH)
    else:
        abstract = doc.styles["Journal Abstract"]
    set_style_font(abstract, BODY_FONT, 10.0)
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


def prepare_lines(lines, anonymous):
    if not anonymous:
        return lines

    omitted = {
        "**민우**",
        "정보보안학과·CCIT 융합전공",
        "원고 작성·최종 자동검증 기준일: 2026년 7월 30일",
        "검증 대상 코드: `KPIIGD/My-AI-Security-Project`, commit `694ca717dd47e3d8f229bfa4da84c1fad607576b`",
    }
    replacements = {
        "본 연구는 KPIIGD 조직의 네 저장소와 로컬 개인 포크를 검토하였다.": (
            "본 연구는 네 저장소와 로컬 검증 복제본을 검토하였다. "
            "익명 심사를 위해 저장소 명칭과 공개 링크는 게재 확정 후 제시한다."
        ),
        "| `KPIIGD/My-AI-Security-Project` | `694ca717dd47` | 코드·10,000건 데이터·저장 실험 결과 |": (
            "| 저장소 A | 익명 검증본 | 코드·10,000건 데이터·저장 실험 결과 |"
        ),
        "| `KPIIGD/My-AI-Security-Project-internal` | `6e9c6beef29d` | 논문 목차·내부 검증문서 |": (
            "| 저장소 B | 익명 검증본 | 논문 목차·내부 검증문서 |"
        ),
        "| `KPIIGD/My-AI-Security-Project-data` | `cc6288d0d868` | 약한 라벨 큐레이션 결과 |": (
            "| 저장소 C | 익명 검증본 | 약한 라벨 큐레이션 결과 |"
        ),
        "| `KPIIGD/ai-security-kb` | `72f8eb17a38c` | 지식베이스·과거 실험 기록 |": (
            "| 저장소 D | 익명 검증본 | 지식베이스·과거 실험 기록 |"
        ),
    }
    result = []
    for line in lines:
        if line in omitted:
            continue
        result.append(replacements.get(line, line))
    return result


def build(output=OUTPUT, anonymous=False):
    source_lines = SOURCE.read_text(encoding="utf-8").splitlines()
    lines = prepare_lines(source_lines, anonymous)
    doc = Document()
    configure_page(doc)
    configure_styles(doc)

    in_abstract = False
    in_english_abstract = False
    in_references = False
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
            title_text = line[2:].replace("Layer 0의", "Layer\u00a00의")
            run = p.add_run(title_text)
            set_font(run, name=HEADING_FONT, size=15, bold=True)
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
            in_abstract = text in ("국문초록", "Abstract", "ABSTRACT")
            in_english_abstract = text == "ABSTRACT"
            if text == "참 고 문 헌":
                in_references = True
            elif in_abstract:
                in_references = False
            if in_abstract:
                p = doc.add_paragraph()
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p.paragraph_format.space_before = Pt(10)
                p.paragraph_format.space_after = Pt(7)
                run = p.add_run(text)
                set_font(run, name=BODY_FONT, size=13.0, bold=True)
            elif text == "참 고 문 헌":
                p = doc.add_paragraph()
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p.paragraph_format.space_before = Pt(10)
                p.paragraph_format.space_after = Pt(7)
                p.paragraph_format.keep_with_next = True
                run = p.add_run(text)
                set_font(run, name=HEADING_FONT, size=14.0, bold=True)
            else:
                p = add_heading(doc, text, 1)
                if text == "Ⅰ. 서론":
                    p.paragraph_format.page_break_before = True
        elif line.startswith("## "):
            text = line[3:]
            if text == "국문초록":
                in_abstract = True
                p = doc.add_paragraph()
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p.paragraph_format.space_before = Pt(10)
                p.paragraph_format.space_after = Pt(7)
                run = p.add_run("〈요 약〉")
                set_font(run, name=BODY_FONT, size=13.0, bold=True)
            elif text == "목 차":
                in_abstract = False
                p = doc.add_paragraph()
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p.paragraph_format.space_before = Pt(8)
                p.paragraph_format.space_after = Pt(5)
                run = p.add_run(text)
                set_font(run, name=HEADING_FONT, size=11.0, bold=True)
            elif in_abstract and text.startswith("*Korean "):
                p = doc.add_paragraph()
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p.paragraph_format.space_after = Pt(5)
                run = p.add_run(text.strip("*"))
                set_font(run, name=BODY_FONT, size=13.0, bold=True)
            else:
                add_heading(doc, text, 2)
        elif line.startswith("### "):
            add_heading(doc, line[4:], 3)
        elif line.startswith("#### "):
            add_heading(doc, line[5:], 3)
        elif line.startswith("- "):
            add_bulleted_paragraph(doc, line[2:])
        elif re.match(r"^\d+\.\s+", line):
            add_numbered_paragraph(doc, line)
        elif not seen_main_body and line.startswith("**민우"):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            p.paragraph_format.space_after = Pt(2)
            add_inline(p, line, size=11.0)
        elif not seen_main_body:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            p.paragraph_format.space_after = Pt(2)
            add_inline(p, line, size=8.8, color=MUTED)
        elif re.match(r"^\*\*<표 \d+>", line):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(5)
            p.paragraph_format.space_after = Pt(3)
            add_inline(p, line, size=10.0)
            for run in p.runs:
                set_font(run, name=HEADING_FONT, size=10.0, bold=True)
        elif line.startswith("자료:"):
            p = add_body_paragraph(doc, line, indent=False, size=8.5)
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        elif in_abstract or line.startswith("**주제어:**") or line.startswith("**Keywords:**") or line.startswith("**Key Words:**"):
            is_keywords = line.startswith(("**주제어:**", "**Keywords:**", "**Key Words:**"))
            p = add_body_paragraph(
                doc,
                line,
                style="Journal Abstract",
                indent=False,
                size=10.0,
            )
            if is_keywords:
                p.paragraph_format.space_before = Pt(10)
            else:
                p.paragraph_format.first_line_indent = Mm(7)
            if in_english_abstract or line.startswith(("**Keywords:**", "**Key Words:**")):
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        else:
            p = add_body_paragraph(doc, line)
            if in_references:
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                p.paragraph_format.left_indent = Mm(7)
                p.paragraph_format.first_line_indent = Mm(-7)
        idx += 1

    core = doc.core_properties
    core.title = (
        "생성형 AI의 한국어 개인식별정보(PII) 유출 위험과 "
        "정규화 기반 Layer 0의 필요성"
    )
    core.subject = (
        "「범죄와 정책」 심사용 익명원고"
        if anonymous
        else "「범죄와 정책」 투고 검증본"
    )
    core.keywords = "생성형 인공지능, 개인정보, 가드레일, Layer 0, 형사정책"
    core.author = ""
    core.last_modified_by = ""
    core.comments = ""
    doc.save(output)
    normalize_docx_archive(output, scrub_metadata=anonymous)
    print(output)


if __name__ == "__main__":
    build()
    build(ANONYMOUS_OUTPUT, anonymous=True)
