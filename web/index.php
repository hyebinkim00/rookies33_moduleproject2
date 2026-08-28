<?php

session_start();

require_once __DIR__ . '/src/inquiry/getRecent.php';

?>

<!DOCTYPE html>
<html lang="ko">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>시민의소리</title>

    <link
        rel="stylesheet"
        href="/assets/css/common.css"
    >

    <link
        rel="stylesheet"
        href="/assets/css/home.css"
    >

</head>

<body>

<?php require_once __DIR__ . '/components/header.php'; ?>


<main>

    <!-- =========================
         메인 히어로
    ========================= -->

    <section class="hero">

        <div class="hero-inner">

            <div class="hero-content">

                <p class="hero-label">
                    온라인 민원 서비스
                </p>

                <h1>
                    시민의 <strong>목소리</strong>를<br>
                    듣겠습니다.
                </h1>

                <p class="hero-description">
                    생활 속 불편사항과 문의사항을<br>
                    쉽고 편리하게 접수하세요.
                </p>

                <div class="hero-buttons">

                    <a
                        href="/inquiry/write.php"
                        class="hero-primary"
                    >
                        민원 신청하기
                    </a>

                    <a
                        href="/inquiry/list.php"
                        class="hero-secondary"
                    >
                        민원 게시판
                    </a>

                </div>

            </div>

        </div>

    </section>


    <!-- =========================
         최근 민원 + 처리 안내
    ========================= -->

    <section class="home-info-section">

        <div class="home-info-inner">


            <!-- 최근 공개 민원 -->

            <div class="recent-box">

                <div class="home-box-header">

                    <h2>
                        최근 공개 민원
                    </h2>

                    <a href="/inquiry/list.php">
                        전체보기 →
                    </a>

                </div>


                <div class="recent-list">

                    <?php if (empty($recentInquiries)): ?>

                        <div class="recent-empty">
                            등록된 공개 민원이 없습니다.
                        </div>

                    <?php else: ?>

                        <?php foreach ($recentInquiries as $inquiry): ?>

                            <a
                                href="/inquiry/detail.php?id=<?= $inquiry['id'] ?>"
                                class="recent-item"
                            >

                                <div class="recent-title">
                                    <?= htmlspecialchars($inquiry['title']) ?>
                                </div>

                                <div class="recent-status">

                                    <?php if ($inquiry['status'] === 'RECEIVED'): ?>

                                        <span class="status-received">
                                            처리중
                                        </span>

                                    <?php elseif ($inquiry['status'] === 'COMPLETED'): ?>

                                        <span class="status-completed">
                                            답변완료
                                        </span>

                                    <?php endif; ?>

                                </div>

                                <div class="recent-date">
                                    <?= date(
                                        'Y-m-d',
                                        strtotime($inquiry['created_at'])
                                    ) ?>
                                </div>

                            </a>

                        <?php endforeach; ?>

                    <?php endif; ?>

                </div>

            </div>


            <!-- 민원 처리 안내 -->

            <div class="process-box">

                <div class="process-header">

                    <h2>
                        민원 처리 안내
                    </h2>

                    <p>
                        접수된 민원은 다음 절차로 처리됩니다.
                    </p>

                </div>


                <div class="process-list">

                    <div class="process-item">

                        <span class="process-number">
                            01
                        </span>

                        <div>

                            <strong>
                                민원 신청
                            </strong>

                            <p>
                                문의 및 불편사항을 작성하여 신청합니다.
                            </p>

                        </div>

                    </div>


                    <div class="process-item">

                        <span class="process-number">
                            02
                        </span>

                        <div>

                            <strong>
                                민원 접수
                            </strong>

                            <p>
                                접수된 민원을 담당자가 확인합니다.
                            </p>

                        </div>

                    </div>


                    <div class="process-item">

                        <span class="process-number">
                            03
                        </span>

                        <div>

                            <strong>
                                답변 완료
                            </strong>

                            <p>
                                처리 결과와 답변을 확인할 수 있습니다.
                            </p>

                        </div>

                    </div>

                </div>


                <a
                    href="/inquiry/write.php"
                    class="process-button"
                >
                    민원 신청하기
                </a>

            </div>


        </div>

    </section>

</main>

</body>

</html>