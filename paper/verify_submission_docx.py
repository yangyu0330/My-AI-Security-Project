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
    assert len(document.tables) == 9
    assert document.core_properties.author == ""
    assert document.core_properties.last_modified_by == ""
    assert document.core_properties.title == (
        "생성형 AI의 한국어 개인식별정보(PII) 유출 위험과 "
        "정규화 기반 Layer 0의 필요성"
    )

    required_text = (
        "생성형 AI의 한국어 개인식별정보(PII) 유출 위험과 정규화 기반 Layer 0의 필요성",
        "Korean Personally Identifiable Information Leakage Risks in Generative AI",
        "9,964건(99.64%)",
        "1,354건",
        "9.12%에서 18.75%",
        "Layer 0",
        "성별·젠더 변수를 포함하지 않은 시스템 감사",
        "A Lifestyle-Routine Activity Theory (LRAT) Approach",
        "presidio.dataprivacystack.org/supported_entities/",
        "1,519개 중 29개(1.91%)",
        "693개 중 48개(6.93%)",
        "의료 265개 중 44개(16.60%)",
        "개발문서 255개 중 4개(1.57%)",
        "조문별 시행일은 국가법령정보센터 공식 XML에서 모두 2026년 1월 22일",
    )
    for claim in required_text:
        assert claim in text, claim

    forbidden_text = (
        "변이 사례의 미차단율은 원형보다 3.93배",
        "2026년 7월 21일 시행된 「인공지능 발전과 신뢰 기반 조성 등에 관한 기본법」",
        "생성형 AI의 한국어 민감정보 유출 위험과 정규화 기반 Layer 0의 필요성",
        "Korean Sensitive-Information Leakage Risks in Generative AI",
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
        "word_page_count_external_check": 19,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
