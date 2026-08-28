from transformers import pipeline

# SQL Injection 탐지 모델 로드
sqli_detector = pipeline(
    "text-classification",
    model="cssupport/mobilebert-sql-injection-detect"
)


def analyze_sqli(text):
    result = sqli_detector(text)[0]

    label = result["label"]
    score = result["score"]

    status = "SQL Injection 의심" if label == "LABEL_1" else "정상 입력"

    return {
        "status": status,
        "label": label,
        "score": score
    }