<?php

session_start();

if (!isset($_SESSION['user_id'])) {

    http_response_code(401);

    echo "
        <script>
            alert('로그인이 필요합니다.');
            location.href = '/auth/login.php';
        </script>
    ";

    exit;
}

require_once __DIR__ . '/../src/inquiry/getMyList.php';


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

    <title>나의 민원 | 시민의소리</title>

    <link
        rel="stylesheet"
        href="/assets/css/common.css"
    >

    <link
        rel="stylesheet"
        href="/assets/css/inquiry.css"
    >

</head>

<body>

<?php
require_once __DIR__
    . '/../components/header.php';
?>

<main class="inquiry-container">

    <div class="inquiry-header">
        <h2>나의 민원</h2>
    </div>

<div class="inquiry-list-toolbar">

    <div class="inquiry-list-info">
        전체 <?= count($inquiries) ?>건
    </div>

    <?php require __DIR__ . '/../components/inquirySearch.php'; ?>

</div>


    <table class="inquiry-table">

        <colgroup>
            <col class="col-number">
            <col class="col-title">
            <col class="col-applicant">
            <col class="col-status">
            <col class="col-date">
        </colgroup>

        <thead>

        <tr>
            <th>번호</th>
            <th>제목</th>
            <th>공개여부</th>
            <th>처리상태</th>
            <th>신청일</th>
        </tr>

        </thead>

        <tbody>

        <?php if (empty($inquiries)): ?>

            <tr>

                <td
                    colspan="5"
                    class="empty-row"
                >
                    신청한 민원이 없습니다.
                </td>

            </tr>

        <?php else: ?>

            <?php foreach ($inquiries as $inquiry): ?>

                <tr>

                    <td class="number">
                        <?= $inquiry['id'] ?>
                    </td>

                    <td class="title">

                        <a
                            href="/inquiry/detail.php?id=<?= $inquiry['id'] ?>"
                        >
                            <?= htmlspecialchars($inquiry['title']) ?>
                        </a>

                    </td>

                    <td class="applicant">

                        <?php if (
                            $inquiry['visibility'] === 'PUBLIC'
                        ): ?>

                            공개

                        <?php else: ?>

                            비공개

                        <?php endif; ?>

                    </td>

                    <td class="status">

                        <?= getStatusText(
                            $inquiry['status']
                        ) ?>

                    </td>

                    <td class="date">

                        <?= date(
                            'Y-m-d',
                            strtotime($inquiry['created_at'])
                        ) ?>

                    </td>

                </tr>

            <?php endforeach; ?>

        <?php endif; ?>

        </tbody>

    </table>


    <div class="list-button-area">

        <a
            href="/inquiry/write.php"
            class="write-btn"
        >
            민원 신청
        </a>

    </div>

</main>

</body>

</html>