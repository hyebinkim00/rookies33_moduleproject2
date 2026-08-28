<?php
session_start();
require_once __DIR__ . '/../src/inquiry/getList.php';
require_once __DIR__ . '/../src/inquiry/delete.php';
require_once __DIR__ . '/../src/users/getList.php';
require_once __DIR__ . '/../src/users/delete.php';



if (!isset($_SESSION["user"])) {
    header("Location: /auth/login.php");
    exit;
}

if (!isset($_SESSION["role"]) || $_SESSION["role"] !== "ADMIN") {
    echo "
        <script>
            alert('관리자만 접근가능한 페이지입니다.');
            location.href = '/';
        </script>
    ";
}

// 통계
$user_count = count($users);
$post_count = count($inquiries);

$waiting_count = 0;

foreach ($inquiries as $inquiry) {

    if ($inquiry['status'] === 'RECEIVED') {
        $waiting_count++;
    }

}

?>

<!DOCTYPE html>
<html lang="ko">

<head>

    <link rel="stylesheet" href="/assets/css/admin.css">
    <meta charset="UTF-8">

    <title>관리자 페이지</title>

</head>


<body>

    <div class="container">


        <!-- =========================
         사이드바
    ========================= -->

        <aside class="sidebar">

            <h2>관리자용</h2>

            <ul class="menu">

                <li>
                    <a href="#dashboard">
                        📊 대시보드
                    </a>
                </li>

                <li>
                    <a href="#users">
                        👤 회원 관리
                    </a>
                </li>

                <li>
                    <a href="#posts">
                        📝 게시글 관리
                    </a>
                </li>

                <li>
                    <a href="/">
                        🏠 사이트로 이동
                    </a>
                </li>

                <li>
                    <a href="../auth/logout.php">
                        🚪 로그아웃
                    </a>
                </li>

            </ul>

        </aside>


        <!-- =========================
         메인
    ========================= -->

        <main class="main">


            <!-- 헤더 -->

            <div class="header" id="dashboard">

                <h1>
                    관리자 대시보드
                </h1>

                <div class="admin-info">

                    관리자:

                    <strong>
                        관리자
                    </strong>

                </div>

            </div>


            <!-- =========================
             통계
        ========================= -->

            <div class="cards">

                <div class="card">

                    <h3>
                        전체 회원
                    </h3>

                    <div class="number">
                        <?= $user_count ?>
                    </div>

                </div>


                <div class="card">

                    <h3>
                        전체 게시글
                    </h3>

                    <div class="number">
                        <?= $post_count ?>
                    </div>

                </div>


                <div class="card">

                    <h3>
                        답변 대기 게시글
                    </h3>

                    <div classs="number">
                        <?= $waiting_count ?>
                    </div>

                </div>

            </div>


            <!-- =========================
             회원 관리
        ========================= -->

            <section class="section" id="users">

                <h2>
                    👤 회원 관리
                </h2>

                <table>

                    <thead>

                        <tr>
                            <th>ID</th>
                            <th>아이디</th>
                            <th>이름</th>
                            <th>권한</th>
                            <th>가입일</th>
                            <th>관리</th>
                        </tr>

                    </thead>


                    <tbody>

                        <?php foreach ($users as $user): ?>

                            <tr>

                                <td>
                                    <?= $user["id"] ?>
                                </td>

                                <td>
                                    <?= htmlspecialchars($user["login_id"]) ?>
                                </td>

                                <td>
                                    <?= htmlspecialchars($user["name"]) ?>
                                </td>

                                <td>
                                    <?= $user["role"] ?>
                                </td>

                                <td>
                                    <?= $user["created_at"] ?>
                                </td>

                                <td>

                                    <?php if ($user["role"] === "ADMIN"): ?>

                                        -

                                    <?php else: ?>

                                        <!-- 회원 삭제 버튼 -->
                                        <form method="POST" onsubmit="return confirm('정말 삭제하시겠습니까?');" class="delete-form">
                                            <input type="hidden" name="delete_user" value="<?= (int) $user['id'] ?>">

                                            <button type="submit" class="btn delete">
                                                삭제
                                            </button>
                                        </form>

                                    <?php endif; ?>

                                </td>

                            </tr>

                        <?php endforeach; ?>

                    </tbody>

                </table>

            </section>


            <!-- =========================
             게시글 관리
            ========================= -->

            <section class="section" id="posts">

                <h2>
                    📝 게시글 관리
                </h2>


                <table>

                    <thead>

                        <tr>
                            <th>번호</th>
                            <th>제목</th>
                            <th>작성자</th>
                            <th>상태</th>
                            <th>작성일</th>
                            <th>관리</th>
                        </tr>

                    </thead>

                    <tbody>
                        <?php if (empty($inquiries)): ?>

                            <tr>
                                <td colspan="6" class="empty-row">
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
                                        <?= htmlspecialchars($inquiry['title']) ?>
                                    
                                    </td>

                                    <td class="applicant">
                                        <?= htmlspecialchars($inquiry['name']) ?>
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

                                    <!-- 관리 버튼 -->

                                    <td>
                                        <div class="action-buttons">

                                            <!-- 댓글 추가 -->
                                            <button type="button" class="btn answer"
                                                onclick="location.href='/admin/answer.php?id=<?= (int) $inquiry['id'] ?>#comment'">
                                                댓글
                                            </button>

                                            <!-- 게시글 삭제 -->
                                            <form method="POST" class="delete-form" onsubmit="return confirm('정말 삭제하시겠습니까?');">
                                                <input type="hidden" name="delete_inquiry" value="<?= (int) $inquiry['id'] ?>">

                                                <button type="submit" class="btn delete">
                                                    삭제
                                                </button>
                                            </form>

                                        </div>
                                    </td>


                                </tr>


                            <?php endforeach; ?>

                        <?php endif; ?>


                    </tbody>

                </table>

            </section>


        </main>

    </div>

</body>

</html>