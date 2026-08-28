<?php
session_start();

require_once __DIR__ . '/../src/inquiry/getDetail.php';


if (!isset($_SESSION['user_id'])) {

    http_response_code(401);
    echo "
        <script>
            alert('로그인이 필요합니다.');
            location.href = '/auth/login.php';
        </script>
    ";
}


function maskName($name)
{   
    $length = mb_strlen($name, 'UTF-8');

    if ($length <= 1) {
        return $name;
    }

    return mb_substr($name, 0, 1, 'UTF-8')
        . str_repeat('*', $length - 1);
}

function getStatusText($status)
{
    if ($status === 'RECEIVED') {
        return '처리중';
    }

    if ($status === 'COMPLETED') {
        return '답변완료';
    }

    return $status;
}

?>

<!DOCTYPE html>
<html lang="ko">

<head>
    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>민원 상세</title>

    <link
        rel="stylesheet"
        href="/assets/css/inquiry.css"
    >

    <link
        rel="stylesheet"
        href="/assets/css/common.css"
    >
</head>

<body>
<?php require_once __DIR__ . '/../components/header.php'; ?>
<main class="inquiry-container">

    <div class="inquiry-header">
        <h2>민원 상세</h2>
    </div>

    <div class="detail-table">

        <div class="detail-row">

            <div class="detail-label">
                제목
            </div>

            <div class="detail-content">
                <?= $inquiry['title'] ?>
            </div>

        </div>

        <div class="detail-row">

            <div class="detail-label">
                민원인
            </div>

            <div class="detail-content">
                <?= maskName($inquiry['user_name']) ?>
            </div>

        </div>

        <div class="detail-row">

            <div class="detail-label">
                공개 여부
            </div>

            <div class="detail-content">
                <?php if ($inquiry['visibility'] === 'PUBLIC'): ?>
                    공개
                <?php else: ?>
                    비공개
                <?php endif; ?>
            </div>

        </div>

        <div class="detail-row">

            <div class="detail-label">
                처리상태
            </div>

            <div class="detail-content">
                <?= getStatusText($inquiry['status']) ?>
            </div>

        </div>

        <div class="detail-row">

            <div class="detail-label">
                신청일
            </div>

            <div class="detail-content">
                <?= date(
                    'Y-m-d H:i',
                    strtotime($inquiry['created_at'])
                ) ?>
            </div>

        </div>

        <div class="detail-row detail-content-row">

            <div class="detail-label">
                민원내용
            </div>

            <div class="detail-content detail-text">
                <?= nl2br($inquiry['content']) ?>
            </div>

        </div>

        <?php if (!empty($inquiryFiles)): ?>

            <div class="detail-row">

                <div class="detail-label">
                    첨부파일
                </div>

                <div class="detail-content">

                    <?php foreach ($inquiryFiles as $file): ?>

                        <div class="attachment-item">
                            <a href="<?= $file['file_path'] ?>">
                                <?= $file['original_filename'] ?>
                            </a>
                        </div>

                    <?php endforeach; ?>

                </div>

            </div>

<?php endif; ?>

    </div>


    <?php if (!empty($inquiry['answer'])): ?>

        <div class="answer-section">

            <div class="answer-header">

                <div>
                    <strong>담당자 답변</strong>

                    <?php if (!empty($inquiry['answer_user_name'])): ?>

                        <span class="answer-user">
                            <?= $inquiry['answer_user_name'] ?>
                        </span>

                    <?php endif; ?>

                </div>

                <?php if (!empty($inquiry['answered_at'])): ?>

                    <span>
                        <?= date(
                            'Y-m-d H:i',
                            strtotime($inquiry['answered_at'])
                        ) ?>
                    </span>

                <?php endif; ?>

            </div>

            <div class="answer-content">
                <?= nl2br($inquiry['answer']) ?>
            </div>

        </div>

    <?php endif; ?>


    <div class="detail-button-area">

        <a
            href="/inquiry/list.php"
            class="write-btn"
        >
            목록
        </a>

    </div>

</main>

</body>

</html>