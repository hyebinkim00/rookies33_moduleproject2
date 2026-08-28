<?php
session_start();
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>민원 작성</title>

    <link rel="stylesheet" href="/assets/css/inquiry.css">

    <link rel="stylesheet" href="/assets/css/common.css" >
</head>

<body>
<?php require_once __DIR__ . '/../components/header.php'; ?>
<div class="inquiry-container">
    
    <div class="inquiry-header">
        <h2>민원내용</h2>
    </div>

    <form
        action="/src/inquiry/create.php"
        method="POST"
        enctype="multipart/form-data"
    >

        <!-- 제목 -->
        <div class="form-row">

            <div class="form-label">
                제목 <span>*</span>
            </div>

            <div class="form-content title-wrapper">

                <input
                    type="text"
                    id="title"
                    name="title"
                    maxlength="50"
                    required
                >

                <div class="counter">
                    <span id="title-count">0</span> / 50
                </div>

            </div>

        </div>


        <!-- 공개 여부 -->
        <div class="form-row">

            <div class="form-label">
                공개 여부 <span>*</span>
            </div>

            <div class="form-content visibility-content">

                <label class="visibility-option">
                    <input
                        type="radio"
                        name="visibility"
                        value="PUBLIC"
                        checked
                    >
                    공개
                </label>

                <label class="visibility-option">
                    <input
                        type="radio"
                        name="visibility"
                        value="PRIVATE"
                    >
                    비공개
                </label>

                <p class="visibility-guide">
                    ※ 비공개 민원은 작성자와 관리자만 내용을 확인할 수 있습니다.
                </p>

            </div>

        </div>


        <!-- 내용 -->
        <div class="form-row content-row">

            <div class="form-label">
                내용 <span>*</span>
            </div>

            <div class="form-content">

                <textarea
                    id="content"
                    name="content"
                    maxlength="5000"
                    required
                    placeholder="문의 내용을 입력해주세요."
                ></textarea>

                <div class="counter content-counter">
                    <span id="content-count">0</span> / 5,000
                </div>

            </div>

        </div>


        <!-- 첨부파일 -->
        <div class="form-row file-row">

            <div class="form-label">
                파일첨부
            </div>

            <div class="form-content">

                <div class="file-box">

                    <input
                        type="file"
                        name="attachments[]"
                        multiple
                    >

                </div>

                <p class="file-guide">
                    ※ 첨부 가능한 파일을 선택해주세요.
                </p>

                <p class="file-guide">
                    ※ 여러 개의 파일을 첨부할 수 있습니다.
                </p>

                <p class="file-guide">
                    ※ 최대 25MB 이하로 첨부할 수 있습니다.
                </p>

            </div>

        </div>


        <!-- 등록 -->
        <div class="button-area">

            <button
                type="submit"
                class="submit-btn"
            >
                등록
            </button>

        </div>

    </form>

</div>


<script>

const title = document.getElementById('title');
const content = document.getElementById('content');

const titleCount = document.getElementById('title-count');
const contentCount = document.getElementById('content-count');

title.addEventListener('input', function () {
    titleCount.textContent = title.value.length;
});

content.addEventListener('input', function () {
    contentCount.textContent = content.value.length;
});

</script>

</body>
</html>