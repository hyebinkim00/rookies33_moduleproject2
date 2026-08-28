<?php

session_start();

require_once __DIR__ . '/../src/db.php';
require_once __DIR__ . '/../src/inquiry/getList.php';

// 이름 마스킹: 김도율 -> 김**
function maskName($name)
{
    $length = mb_strlen($name, 'UTF-8');

    if ($length <= 1) {
        return $name;
    }

    return mb_substr($name, 0, 1, 'UTF-8')
        . str_repeat('*', $length - 1);
}

?>

<!DOCTYPE html>
<html lang="ko">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>공개 민원</title>

    <link rel="stylesheet" href="/assets/css/inquiry.css">

    <link
        rel="stylesheet"
        href="/assets/css/common.css"
    >

</head>

<body>
<?php require_once __DIR__ . '/../components/header.php'; ?>
<main class="inquiry-container">

    <div class="inquiry-header">
        <h2>공개 민원</h2>
    </div>

    <div class="inquiry-list-toolbar">

        <div class="inquiry-list-info">
            전체 <?= count($inquiries) ?>건
        </div>

        <?php require __DIR__ . '/../components/inquirySearch.php'; ?>

    </div>
    <table class="inquiry-table">

        <thead>
        <tr>
            <th class="number">번호</th>
            <th class="title">제목</th>
            <th class="applicant">민원인</th>
            <th class="status">처리상태</th>
            <th class="date">신청일</th>
        </tr>
        </thead>

        <tbody>

        <?php if (empty($inquiries)): ?>

            <tr>
                <td colspan="5" class="empty-row">
                    등록된 민원이 없습니다.
                </td>
            </tr>

        <?php else: ?>

            <?php foreach ($inquiries as $inquiry): ?>

                <tr>

                    <td class="number">
                        <?= $inquiry['id'] ?>
                    </td>

                    <td class="title">
                        <a href="/inquiry/detail.php?id=<?= $inquiry['id'] ?>">
                            <?= $inquiry['title'] ?>
                        </a>
                    </td>

                    <td class="applicant">
                        <?= maskName($inquiry['name']) ?>
                    </td>

                    <td class="status">

                        <?php if ($inquiry['status'] === 'RECEIVED'): ?>

                            <span class="status-received">
                                처리중
                            </span>

                        <?php elseif ($inquiry['status'] === 'COMPLETED'): ?>

                            <span class="status-completed">
                                답변완료
                            </span>

                        <?php endif; ?>

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

        <a href="/inquiry/write.php" class="write-btn">
            민원 신청
        </a>

    </div>

</main>

</body>

</html>