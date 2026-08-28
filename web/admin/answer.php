<?php

session_start();

require_once __DIR__ . '/../src/db.php';


/* ==========================
   관리자 확인
========================== */

if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'ADMIN') {

    echo "
        <script>
            alert('관리자만 접근가능한 페이지입니다.');
            location.href = '/';
        </script>
    ";

    exit;
}


/* ==========================
   답변 등록
========================== */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $inquiry_id = $_POST['inquiry_id'] ?? 0;
    $answer = trim($_POST['answer'] ?? '');

    if (!$inquiry_id || $answer === '') {

        echo "<script>
            alert('답변 내용을 입력해주세요.');
            history.back();
        </script>";

        exit;
    }


    $sql = "
        UPDATE inquiry
        SET
            answer = :answer,
            answered_by = :answered_by,
            answered_at = NOW(),
            status = 'COMPLETED'
        WHERE id = :id
    ";

    $stmt = $pdo->prepare($sql);

    $stmt->execute([
        ':answer'      => $answer,
        ':answered_by' => $_SESSION['user_id'],
        ':id'          => $inquiry_id
    ]);


    echo "<script>
        alert('답변이 등록되었습니다.');
        location.href='admin.php';
    </script>";

    exit;
}


/* ==========================
   선택한 민원 조회
========================== */

$id = $_GET['id'] ?? 0;

$inquiry = null;


if ($id) {

    $sql = "
        SELECT
            i.id,
            i.title,
            i.content,
            i.answer,
            i.answered_at,
            i.status,
            i.created_at,

            u.name AS user_name,

            a.name AS admin_name

        FROM inquiry i

        LEFT JOIN users u
            ON i.user_id = u.id

        LEFT JOIN users a
            ON i.answered_by = a.id

        WHERE i.id = :id
    ";

    $stmt = $pdo->prepare($sql);

    $stmt->execute([
        ':id' => $id
    ]);

    $inquiry = $stmt->fetch(PDO::FETCH_ASSOC);
}

?>


<!DOCTYPE html>
<html lang="ko">

<head>

    <link
        rel="stylesheet"
        href="/assets/css/answer.css"
    >
    <meta charset="UTF-8">

    <title>관리자 답변</title>

</head>


<body>


<div class="container">


    <a href="admin.php" class="back">
        ← 민원 목록
    </a>


    <?php if ($inquiry): ?>


        <!-- ==========================
             민원 내용
        =========================== -->

        <div class="card">

            <h1>민원 내용</h1>


            <div class="title">
                <?= htmlspecialchars($inquiry['title']) ?>
            </div>


            <div class="info">

                <span>
                    작성자 :
                    <?= htmlspecialchars($inquiry['user_name']) ?>
                </span>


                <span>
                    작성일 :
                    <?= htmlspecialchars($inquiry['created_at']) ?>
                </span>

            </div>


            <div class="inquiry-content">
                <?= nl2br($inquiry['content']) ?>
            </div>

        </div>


        <!-- ==========================
             기존 댓글
        =========================== -->

        <div class="card" id="comment">

            <h2>댓글</h2>


            <?php if (!empty($inquiry['answer'])): ?>


                <div class="answer-box">


                    <div class="answer-header">

                        <span class="admin-name">
                            <?= htmlspecialchars(
                                $inquiry['admin_name'] ?? '관리자'
                            ) ?>
                        </span>


                        <span class="date">
                            <?= htmlspecialchars(
                                $inquiry['answered_at']
                            ) ?>
                        </span>

                    </div>


                    <div class="answer-content">
                        <?= nl2br($inquiry['answer']) ?> 
                    </div>


                </div>


            <?php else: ?>


                <div class="no-answer">
                    아직 등록된 댓글이 없습니다.
                </div>


            <?php endif; ?>


        </div>


        <!-- ==========================
             댓글 추가
        =========================== -->

        <div class="card">

            <h2>댓글 추가</h2>


            <form method="POST">


                <input
                    type="hidden"
                    name="inquiry_id"
                    value="<?= (int)$inquiry['id'] ?>"
                >


                <textarea
                    name="answer"
                    placeholder="댓글을 입력해주세요."
                    required
                ></textarea>


                <button type="submit">
                    댓글 등록
                </button>


            </form>

        </div>


    <?php else: ?>


        <div class="card">
            민원을 찾을 수 없습니다.
        </div>


    <?php endif; ?>


</div>


</body>

</html>