from io import BytesIO
import html
import os

from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether
)

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie


def safe_text(value):
    if value is None:
        return ""
    return html.escape(str(value))


def make_paragraph(value, style):
    return Paragraph(
        safe_text(value),
        style
    )


def register_korean_font():
    font_candidates = [
        "C:/Windows/Fonts/malgun.ttf",
        "C:/Windows/Fonts/NanumGothic.ttf",
        "C:/Windows/Fonts/gulim.ttc"
    ]

    for font_path in font_candidates:
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(
                    TTFont(
                        "Korean",
                        font_path
                    )
                )
                return
            except Exception:
                continue

    raise RuntimeError(
        "한글 PDF 출력을 위한 폰트를 찾을 수 없습니다."
    )


def clean_summary_evidence(value):
    if value is None:
        return "-"

    text = str(value)
    marker = " / 취약 탐지 파일:"

    if marker in text:
        text = text.split(marker, 1)[0]

    return text


def extension_only(value):
    if value is None:
        return "-"

    text = str(value)

    extension = (
        os.path.splitext(text)[1]
        .lstrip(".")
        .upper()
    )

    if extension:
        return extension

    return text


def result_target_label(item):
    """
    PDF 요약표에 표시할 진단 대상을 정리합니다.

    - 파일 업로드 진단: tested_files/source_file에서 확장자만 추출
    - 그 외 웹 진단: WEB
    """

    if item.get("source_type") != "파일 업로드 진단":
        return "WEB"

    filenames = item.get("tested_files")

    if not isinstance(filenames, list):
        filenames = []

    if not filenames:
        source_file = item.get("source_file")
        if source_file and source_file != "다중 파일":
            filenames = [source_file]

    extensions = []

    for filename in filenames:
        extension = (
            os.path.splitext(str(filename))[1]
            .lstrip(".")
            .upper()
        )

        if extension and extension not in extensions:
            extensions.append(extension)

    if extensions:
        return ", ".join(extensions)

    return "-"


def generate_pdf_report(
    results,
    hf_result=None,
    target_name="공공 민원포털 웹 서비스"
):
    buffer = BytesIO()

    register_korean_font()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=45,
        leftMargin=45,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    cover_title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontName="Korean",
        fontSize=27,
        leading=40,
        alignment=TA_CENTER
    )

    cover_sub_style = ParagraphStyle(
        "CoverSub",
        parent=styles["Normal"],
        fontName="Korean",
        fontSize=12,
        leading=20,
        alignment=TA_CENTER
    )

    toc_title_style = ParagraphStyle(
        "TocTitle",
        parent=styles["Heading1"],
        fontName="Korean",
        fontSize=25,
        leading=32,
        alignment=TA_LEFT,
        spaceAfter=20
    )

    toc_item_style = ParagraphStyle(
        "TocItem",
        parent=styles["Normal"],
        fontName="Korean",
        fontSize=14,
        leading=25,
        leftIndent=15
    )

    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading1"],
        fontName="Korean",
        fontSize=17,
        leading=24,
        spaceBefore=8,
        spaceAfter=10
    )

    sub_style = ParagraphStyle(
        "SubSection",
        parent=styles["Heading2"],
        fontName="Korean",
        fontSize=13,
        leading=19,
        spaceBefore=8,
        spaceAfter=7
    )

    normal_style = ParagraphStyle(
        "NormalKorean",
        parent=styles["Normal"],
        fontName="Korean",
        fontSize=9.5,
        leading=15,
        alignment=TA_LEFT
    )

    center_style = ParagraphStyle(
        "CenterKorean",
        parent=normal_style,
        alignment=TA_CENTER
    )

    elements = []

    total = len(results)

    vulnerable = sum(
        1
        for item in results
        if item["status"] == "취약"
    )

    safe = sum(
        1
        for item in results
        if item["status"] == "양호"
    )

    na = sum(
        1
        for item in results
        if item["status"] == "N/A"
    )

    high_risk = sum(
        1
        for item in results
        if item.get("risk") == "높음"
    )

    medium_risk = sum(
        1
        for item in results
        if item.get("risk") == "중간"
    )

    low_risk = sum(
        1
        for item in results
        if item.get("risk") == "낮음"
    )

    vulnerability_names = " / ".join(
        item["vulnerability"]
        for item in results
    )

    elements.append(
        Spacer(1, 132)
    )

    elements.append(
        Paragraph(
            "진단 결과 보고서",
            cover_title_style
        )
    )

    elements.append(
        Spacer(1, 72)
    )

    elements.append(
        Paragraph(
            f"점검 대상 : {safe_text(target_name)}",
            cover_sub_style
        )
    )

    elements.append(
        Spacer(1, 8)
    )

    elements.append(
        Paragraph(
            "점검 기간 : 2026.08.26 ~ 2026.08.31",
            cover_sub_style
        )
    )

    elements.append(
        Spacer(1, 8)
    )

    elements.append(
        Paragraph(
            "분석 방식 : 자동 진단 · AI 보조 분석",
            cover_sub_style
        )
    )

    elements.append(
        PageBreak()
    )

    elements.append(
        Paragraph(
            "목 차",
            toc_title_style
        )
    )

    elements.append(
        Spacer(1, 15)
    )

    toc_items = [
        "1. 점검 개요",
        "2. 진단 결과 요약",
        "3. 상세 수행 결과",
        "4. AI 기반 보조 분석",
        "5. 종합 대응방안"
    ]

    for item in toc_items:
        elements.append(
            Paragraph(
                item,
                toc_item_style
            )
        )

        elements.append(
            Spacer(1, 7)
        )

    elements.append(
        PageBreak()
    )

    elements.append(
        Paragraph(
            "1. 점검 개요",
            section_style
        )
    )

    overview_data = [
        ["구분", "내용"],
        [
            "점검 대상",
            make_paragraph(
                target_name,
                normal_style
            )
        ],
        [
            "점검 기간",
            "2026.08.26 ~ 2026.08.31"
        ],
        [
            "점검 항목",
            make_paragraph(
                vulnerability_names,
                normal_style
            )
        ],
        [
            "점검 방식",
            make_paragraph(
                "Python 기반 자동 진단 결과 분석 및 "
                "수동 진단 결과 비교",
                normal_style
            )
        ],
        [
            "AI 활용",
            make_paragraph(
                "OpenAI 기반 결과 분석 및 "
                "Hugging Face 기반 SQL Injection 보조 분석",
                normal_style
            )
        ]
    ]

    overview_table = Table(
        overview_data,
        colWidths=[100, 360]
    )

    overview_table.setStyle(
        TableStyle([
            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Korean"
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                HexColor("#D9E2F3")
            ),
            (
                "BACKGROUND",
                (0, 1),
                (0, -1),
                HexColor("#F2F2F2")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                HexColor("#7F8C8D")
            ),
            (
                "ALIGN",
                (0, 0),
                (0, -1),
                "CENTER"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    elements.append(
        overview_table
    )

    elements.append(
        Spacer(1, 20)
    )

    elements.append(
        Paragraph(
            "2. 진단 결과 요약",
            section_style
        )
    )

    summary_data = [
        [
            "구분",
            "판정",
            "",
            "",
            "",
            "위험도",
            "",
            ""
        ],
        [
            "",
            "전체",
            "취약",
            "양호",
            "N/A",
            "높음",
            "중간",
            "낮음"
        ],
        [
            "건수",
            f"{total}건",
            f"{vulnerable}건",
            f"{safe}건",
            f"{na}건",
            f"{high_risk}건",
            f"{medium_risk}건",
            f"{low_risk}건"
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            58,
            58,
            58,
            58,
            58,
            58,
            58,
            58
        ]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "SPAN",
                (1, 0),
                (4, 0)
            ),
            (
                "SPAN",
                (5, 0),
                (7, 0)
            ),
            (
                "SPAN",
                (0, 0),
                (0, 1)
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Korean"
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 1),
                HexColor("#D9E2F3")
            ),
            (
                "BACKGROUND",
                (0, 2),
                (-1, 2),
                HexColor("#FFFFFF")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                HexColor("#7F8C8D")
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    elements.append(
        summary_table
    )

    elements.append(
        Spacer(1, 15)
    )

    chart_title_style = ParagraphStyle(
        "ChartTitle",
        parent=sub_style,
        alignment=TA_CENTER,
        spaceBefore=2,
        spaceAfter=8
    )

    elements.append(
        Paragraph(
            "진단 결과 분포",
            chart_title_style
        )
    )

    # 판정 분포 원형 그래프
    status_drawing = Drawing(
        220,
        185
    )

    status_pie = Pie()
    status_pie.x = 42
    status_pie.y = 18
    status_pie.width = 135
    status_pie.height = 135

    status_distribution = [
        ("취약", vulnerable, HexColor("#E57373")),
        ("양호", safe, HexColor("#64B5F6")),
        ("N/A", na, HexColor("#B0BEC5"))
    ]

    active_status_distribution = [
        item
        for item in status_distribution
        if item[1] > 0
    ]

    if not active_status_distribution:
        active_status_distribution = [
            ("N/A", 1, HexColor("#B0BEC5"))
        ]

    status_pie.data = [
        item[1]
        for item in active_status_distribution
    ]

    status_total = sum(
        item[1]
        for item in active_status_distribution
    )

    status_pie.labels = [
        f"{name} {count}건\n({count / status_total * 100:.1f}%)"
        for name, count, _ in active_status_distribution
    ]

    status_pie.slices.fontName = "Korean"
    status_pie.slices.fontSize = 8
    status_pie.slices.labelRadius = 1.16
    status_pie.slices.strokeWidth = 0.5
    status_pie.slices.strokeColor = HexColor("#FFFFFF")

    for index, (_, _, color) in enumerate(
        active_status_distribution
    ):
        status_pie.slices[index].fillColor = color

    status_drawing.add(status_pie)

    # 위험도 분포 원형 그래프
    risk_drawing = Drawing(
        220,
        185
    )

    risk_pie = Pie()
    risk_pie.x = 42
    risk_pie.y = 18
    risk_pie.width = 135
    risk_pie.height = 135

    risk_distribution = [
        ("높음", high_risk, HexColor("#E57373")),
        ("중간", medium_risk, HexColor("#FFB74D")),
        ("낮음", low_risk, HexColor("#64B5F6"))
    ]

    active_risk_distribution = [
        item
        for item in risk_distribution
        if item[1] > 0
    ]

    if not active_risk_distribution:
        active_risk_distribution = [
            ("낮음", 1, HexColor("#B0BEC5"))
        ]

    risk_pie.data = [
        item[1]
        for item in active_risk_distribution
    ]

    risk_total = sum(
        item[1]
        for item in active_risk_distribution
    )

    risk_pie.labels = [
        f"{name} {count}건\n({count / risk_total * 100:.1f}%)"
        for name, count, _ in active_risk_distribution
    ]

    risk_pie.slices.fontName = "Korean"
    risk_pie.slices.fontSize = 8
    risk_pie.slices.labelRadius = 1.16
    risk_pie.slices.strokeWidth = 0.5
    risk_pie.slices.strokeColor = HexColor("#FFFFFF")

    for index, (_, _, color) in enumerate(
        active_risk_distribution
    ):
        risk_pie.slices[index].fillColor = color

    risk_drawing.add(risk_pie)

    chart_table = Table(
        [
            [
                Paragraph(
                    "<b>판정 분포</b>",
                    center_style
                ),
                Paragraph(
                    "<b>위험도 분포</b>",
                    center_style
                )
            ],
            [
                status_drawing,
                risk_drawing
            ],
            [
                Paragraph(
                    f"취약 {vulnerable}건 / 양호 {safe}건 / N/A {na}건",
                    center_style
                ),
                Paragraph(
                    f"높음 {high_risk}건 / 중간 {medium_risk}건 / 낮음 {low_risk}건",
                    center_style
                )
            ]
        ],
        colWidths=[
            230,
            230
        ]
    )

    chart_table.setStyle(
        TableStyle([
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                0
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                0
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                2
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                2
            )
        ])
    )

    elements.append(
        chart_table
    )

    elements.append(
        Spacer(1, 8)
    )

    elements.append(
        PageBreak()
    )

    elements.append(
        Paragraph(
            "진단 결과 상세 요약",
            section_style
        )
    )

    result_data = [
        [
            "취약점",
            "진단 대상",
            "판정",
            "위험도",
            "판정 근거"
        ]
    ]

    for item in results:
        result_data.append([
            make_paragraph(
                item["vulnerability"],
                normal_style
            ),
            make_paragraph(
                result_target_label(
                    item
                ),
                center_style
            ),
            make_paragraph(
                item["status"],
                center_style
            ),
            make_paragraph(
                item["risk"],
                center_style
            ),
            make_paragraph(
                (
                    item.get(
                        "reason",
                        "-"
                    )
                    if item.get("status") == "취약"
                    else clean_summary_evidence(
                        item.get(
                            "evidence",
                            "-"
                        )
                    )
                ),
                normal_style
            )
        ])

    result_table = Table(
        result_data,
        colWidths=[
            85,
            55,
            45,
            45,
            230
        ],
        repeatRows=1
    )

    result_table.setStyle(
        TableStyle([
            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Korean"
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                HexColor("#D9E2F3")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                HexColor("#7F8C8D")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "ALIGN",
                (1, 1),
                (3, -1),
                "CENTER"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    elements.append(
        result_table
    )

    elements.append(
        PageBreak()
    )

    elements.append(
        Paragraph(
            "3. 상세 수행 결과",
            section_style
        )
    )

    for index, item in enumerate(
        results,
        start=1
    ):
        detail_data = [
            ["구분", "내용"],
            [
                "판정",
                make_paragraph(
                    item["status"],
                    normal_style
                )
            ],
            [
                "위험도",
                make_paragraph(
                    item["risk"],
                    normal_style
                )
            ]
        ]

        if item.get("confidence"):
            detail_data.append([
                "진단 확실성",
                make_paragraph(
                    item["confidence"],
                    normal_style
                )
            ])

        if item.get("source_type") == "파일 업로드 진단":
            detail_data.append([
                "파일 형식",
                make_paragraph(
                    result_target_label(
                        item
                    ),
                    normal_style
                )
            ])

        if item.get("parameter"):
            detail_data.append([
                "진단 대상",
                make_paragraph(
                    item["parameter"],
                    normal_style
                )
            ])

        if (
            item.get("payload")
            and item.get("vulnerability")
            != "파일명 위험 패턴 (Filename Risk Pattern)"
        ):
            detail_data.append([
                "테스트 입력값",
                make_paragraph(
                    item["payload"],
                    normal_style
                )
            ])

        detail_data.extend([
            [
                "탐지 내용",
                make_paragraph(
                    item["evidence"],
                    normal_style
                )
            ],
            [
                "판단 근거",
                make_paragraph(
                    item["reason"],
                    normal_style
                )
            ],
            [
                "대응방안",
                make_paragraph(
                    item["recommendation"],
                    normal_style
                )
            ]
        ])

        detail_table = Table(
            detail_data,
            colWidths=[
                90,
                370
            ]
        )

        detail_table.setStyle(
            TableStyle([
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, -1),
                    "Korean"
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    HexColor("#D9E2F3")
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (0, -1),
                    HexColor("#F2F2F2")
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    HexColor("#7F8C8D")
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (0, -1),
                    "CENTER"
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )
            ])
        )

        block = [
            Paragraph(
                f"3.{index} "
                f"{safe_text(item['vulnerability'])}",
                sub_style
            ),
            detail_table,
            Spacer(
                1,
                12
            )
        ]

        elements.append(
            KeepTogether(block)
        )

    elements.append(
        PageBreak()
    )

    elements.append(
        Paragraph(
            "4. AI 기반 보조 분석",
            section_style
        )
    )

    elements.append(
        Spacer(1, 8)
    )

    elements.append(
        Paragraph(
            "4.1 Hugging Face 기반 "
            "SQL Injection 분석",
            sub_style
        )
    )

    elements.append(
        Spacer(1, 7)
    )

    if hf_result:
        hf_data = [
            ["구분", "내용"],
            [
                "진단 대상",
                make_paragraph(
                    extension_only(
                        hf_result.get(
                            "parameter",
                            "-"
                        )
                    ),
                    normal_style
                )
            ],
            [
                "분석 입력값",
                make_paragraph(
                    hf_result.get(
                        "payload",
                        "-"
                    ),
                    normal_style
                )
            ],
            [
                "AI 분석 결과",
                make_paragraph(
                    hf_result.get(
                        "status",
                        "-"
                    ),
                    normal_style
                )
            ],
            [
                "모델 확신도",
                make_paragraph(
                    f"{hf_result.get('score', 0) * 100:.2f}%",
                    normal_style
                )
            ]
        ]

        hf_table = Table(
            hf_data,
            colWidths=[
                110,
                350
            ]
        )

        hf_table.setStyle(
            TableStyle([
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, -1),
                    "Korean"
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    HexColor("#D9E2F3")
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (0, -1),
                    HexColor("#F2F2F2")
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    HexColor("#7F8C8D")
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (0, -1),
                    "CENTER"
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )
            ])
        )

        elements.append(
            hf_table
        )

        elements.append(
            Spacer(1, 15)
        )

        elements.append(
            Paragraph(
                "해당 결과는 자동 진단 과정에서 확인된 SQL Injection 관련 입력값을 "
                "Hugging Face 분류 모델로 분석한 보조 AI 판정 결과입니다. "
                "본 결과는 입력 문자열에 대한 분류 모델의 보조 판단이며, "
                "실제 취약점 악용 가능성이나 공격 성공 여부를 의미하지 않습니다.",
                normal_style
            )
        )

    else:
        elements.append(
            Paragraph(
                "Hugging Face SQL Injection 보조 분석이 "
                "수행되지 않았거나 분석 결과가 존재하지 않습니다.",
                normal_style
            )
        )

    elements.append(
        Spacer(1, 20)
    )

    elements.append(
        Paragraph(
            "5. 종합 대응방안",
            section_style
        )
    )

    vulnerable_items = [
        item
        for item in results
        if item["status"] == "취약"
    ]

    if vulnerable_items:
        response_data = [
            [
                "취약점",
                "위험도",
                "대응방안"
            ]
        ]

        for item in vulnerable_items:
            response_data.append([
                make_paragraph(
                    item["vulnerability"],
                    normal_style
                ),
                make_paragraph(
                    item["risk"],
                    center_style
                ),
                make_paragraph(
                    item["recommendation"],
                    normal_style
                )
            ])

        response_table = Table(
            response_data,
            colWidths=[
                110,
                70,
                280
            ]
        )

        response_table.setStyle(
            TableStyle([
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, -1),
                    "Korean"
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    HexColor("#D9E2F3")
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    HexColor("#7F8C8D")
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (1, -1),
                    "CENTER"
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )
            ])
        )

        elements.append(
            response_table
        )

    else:
        elements.append(
            Paragraph(
                "현재 자동 진단 결과에서 "
                "취약으로 판정된 항목이 없습니다.",
                normal_style
            )
        )

    elements.append(
        Spacer(1, 20)
    )

    elements.append(
        Paragraph(
            "<종합 의견>",
            sub_style
        )
    )

    if vulnerable > 0:
        high_risk_items = [
            item["vulnerability"]
            for item in vulnerable_items
            if item.get("risk") == "높음"
        ]

        medium_risk_items = [
            item["vulnerability"]
            for item in vulnerable_items
            if item.get("risk") == "중간"
        ]

        overall_text = (
            f"총 {total}개의 점검 항목 중 {vulnerable}개 항목이 취약으로 확인되었습니다. "
        )

        if high_risk_items:
            overall_text += (
                f"고위험 항목 {len(high_risk_items)}건("
                + ", ".join(high_risk_items)
                + ")은 우선 조치가 필요합니다. "
            )

        if medium_risk_items:
            overall_text += (
                f"중위험 항목 {len(medium_risk_items)}건("
                + ", ".join(medium_risk_items)
                + ")은 후속 조치 대상으로 관리하는 것이 권장됩니다. "
            )

        overall_text += (
            "각 취약 항목은 상세 수행 결과의 판단 근거와 대응방안을 기준으로 조치하고, "
            "양호 항목은 현재 상태를 유지하되 정기적인 재점검을 수행하는 것이 권장됩니다."
        )

        if na > 0:
            overall_text += (
                f" N/A 항목 {na}건은 추가 점검을 통해 최종 판정을 수행해야 합니다."
            )
    else:
        overall_text = (
            f"총 {total}개의 점검 항목에서 "
            "취약 판정이 확인되지 않았습니다. "
            "N/A 항목은 추가 확인이 필요하며 "
            "정기적인 재점검이 권장됩니다."
        )

    elements.append(
        Paragraph(
            overall_text,
            normal_style
        )
    )

    doc.build(elements)

    buffer.seek(0)

    return buffer.getvalue()