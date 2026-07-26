"""Structural QA for the generated Crime and Policy submission-review DOCX."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from docx import Document
from docx.oxml.ns import qn


ROOT = Path(__file__).resolve().parents[1]
DOCX = ROOT / "paper" / "범죄와정책_투고원고_검증본.docx"


def dxa(value):
    return int(value / 635)


def main():
    document = Document(DOCX)
    section = document.sections[0]
    text = "\n".join(p.text for p in document.paragraphs)

    expected = {
        "page_width": 11792,   # 208 mm
        "page_height": 15704,  # 277 mm
        "top_margin": 1134,    # 20 mm
        "bottom_margin": 850,  # 15 mm
        "left_margin": 850,
        "right_margin": 850,
        "header_distance": 850,
        "footer_distance": 850,
    }
    actual = {
        "page_width": dxa(section.page_width),
        "page_height": dxa(section.page_height),
        "top_margin": dxa(section.top_margin),
        "bottom_margin": dxa(section.bottom_margin),
        "left_margin": dxa(section.left_margin),
        "right_margin": dxa(section.right_margin),
        "header_distance": dxa(section.header_distance),
        "footer_distance": dxa(section.footer_distance),
    }
    for key, target in expected.items():
        assert abs(actual[key] - target) <= 2, (key, actual[key], target)

    assert len(document.sections) == 1
    assert len(document.tables) == 8
    assert document.core_properties.author == ""
    assert document.core_properties.last_modified_by == ""

    required_text = (
        "9,964건(99.64%)",
        "1,354건",
        "9.12%에서 18.75%",
        "Layer 0",
        "성별·젠더 변수를 포함하지 않은 시스템 감사",
        "A Lifestyle-Routine Activity Theory (LRAT) Approach",
        "presidio.dataprivacystack.org/supported_entities/",
    )
    for claim in required_text:
        assert claim in text, claim

    forbidden_text = (
        "변이 사례의 미차단율은 원형보다 3.93배",
        "**",
        "```",
    )
    for claim in forbidden_text:
        assert claim not in text, claim

    table_geometry = []
    for table_index, table in enumerate(document.tables, 1):
        tbl_pr = table._tbl.tblPr
        tbl_w = tbl_pr.find(qn("w:tblW"))
        tbl_ind = tbl_pr.find(qn("w:tblInd"))
        grid_widths = [
            int(node.get(qn("w:w"))) for node in table._tbl.tblGrid.findall(qn("w:gridCol"))
        ]
        width = int(tbl_w.get(qn("w:w")))
        indent = int(tbl_ind.get(qn("w:w")))
        assert width == sum(grid_widths), (table_index, width, grid_widths)
        assert indent == 120, (table_index, indent)
        assert width == 9970, (table_index, width)
        for row in table.rows:
            for cell_index, cell in enumerate(row.cells):
                tc_w = cell._tc.get_or_add_tcPr().find(qn("w:tcW"))
                assert int(tc_w.get(qn("w:w"))) == grid_widths[cell_index]
        table_geometry.append(
            {"table": table_index, "columns": len(grid_widths), "width_dxa": width}
        )

    result = {
        "file": str(DOCX),
        "sha256": hashlib.sha256(DOCX.read_bytes()).hexdigest(),
        "sections": len(document.sections),
        "paragraphs": len(document.paragraphs),
        "tables": len(document.tables),
        "geometry_dxa": actual,
        "table_geometry": table_geometry,
        "structural_qa": "passed",
        "word_page_count_external_check": 18,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
