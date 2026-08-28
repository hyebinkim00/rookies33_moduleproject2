<header class="site-header">

    <div class="header-inner">

        <a href="/" class="site-logo">
            시민의소리
        </a>

        <nav class="main-nav">

            <a href="/inquiry/write.php">
                민원신청
            </a>

            <a href="/inquiry/list.php">
                민원게시판
            </a>

        </nav>

        <div class="header-user">

            <?php if (isset($_SESSION['user_id'])): ?>

                <span>
                    <?= $_SESSION['name'] ?> 님 환영합니다.
                </span>

                <a href="/inquiry/my.php">
                    나의 민원
                </a>

                <a href="/auth/logout.php" class="logout-link">
                    로그아웃
                </a>

            <?php else: ?>

                <a href="/auth/login.php">
                    로그인
                </a>

                <a href="/auth/register.php">
                    회원가입
                </a>

            <?php endif; ?>

        </div>

    </div>

</header>