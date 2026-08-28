<?php

session_start();

require_once __DIR__ . '/../src/db.php';

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $id = $_POST["id"] ?? "";
    $pw = $_POST["pw"] ?? "";
    $name = $_POST["name"] ?? "";

    if ($id === "" || $pw === "" || $name === "") {

        $error = "모든 항목을 입력해주세요.";

    } else {

        try {

            // 아이디 중복 확인
            $check = $pdo->prepare(
                "SELECT id FROM users WHERE login_id = :id"
            );

            $check->execute([
                ":id" => $id
            ]);

            if ($check->fetch()) {

                $error = "이미 사용 중인 아이디입니다.";

            } else {

                // 비밀번호 해시
                $hash = password_hash(
                    $pw,
                    PASSWORD_DEFAULT
                );

                // 회원정보 저장
                $sql = "
                    INSERT INTO users (
                        login_id,
                        password,
                        name
                    )
                    VALUES (
                        :id,
                        :pw,
                        :name
                    )
                ";

                $stmt = $pdo->prepare($sql);

                $stmt->execute([
                    ":id" => $id,
                    ":pw" => $hash,
                    ":name" => $name
                ]);

                echo "
                    <script>
                        alert('회원가입이 완료되었습니다.');
                        location.href='/auth/login.php';
                    </script>
                ";

                exit;
            }

        } catch (PDOException $e) {

            $error = "회원가입 중 오류가 발생했습니다.";
        }
    }
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

    <title>회원가입 | 시민의소리</title>

    <link
        rel="stylesheet"
        href="/assets/css/common.css"
    >

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;

            font-family:
                Arial,
                "Noto Sans KR",
                sans-serif;

            color: #222;
            background: #f5f7fa;
        }


        /* =========================
           회원가입 영역
        ========================= */

        .register-container {
            width: 430px;
            margin: 70px auto;
        }

        .register-title {
            margin-bottom: 30px;
            text-align: center;
        }

        .register-title h1 {
            margin: 0 0 10px;

            color: #343a72;

            font-size: 28px;
        }

        .register-title p {
            margin: 0;

            color: #777;

            font-size: 14px;
        }


        /* =========================
           회원가입 폼
        ========================= */

        .register-box {
            padding: 35px 40px 40px;

            background: #fff;

            border: 1px solid #dfe3e8;
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group label {
            display: block;

            margin-bottom: 8px;

            color: #333;

            font-size: 14px;
            font-weight: bold;
        }

        .form-group input {
            width: 100%;
            height: 46px;

            padding: 0 13px;

            border: 1px solid #bcc5d1;
            outline: none;

            font-size: 14px;
        }

        .form-group input:focus {
            border-color: #343a72;
        }


        /* =========================
           오류
        ========================= */

        .error {
            margin: 0 0 18px;
            padding: 11px 13px;

            background: #fff3f3;

            border: 1px solid #f0cccc;

            color: #c0392b;

            font-size: 13px;
        }


        /* =========================
           버튼
        ========================= */

        .register-btn {
            width: 100%;
            height: 47px;

            margin-top: 8px;

            border: 0;

            background: #343a72;

            color: #fff;

            font-size: 15px;
            font-weight: bold;

            cursor: pointer;
        }

        .register-btn:hover {
            background: #272c5d;
        }


        /* =========================
           로그인 이동
        ========================= */

        .login-area {
            margin-top: 18px;
            padding-top: 18px;

            border-top: 1px solid #eee;

            text-align: center;
        }

        .login-area span {
            color: #777;

            font-size: 13px;
        }

        .login-link {
            margin-left: 8px;

            color: #343a72;

            font-size: 13px;
            font-weight: bold;

            text-decoration: none;
        }

        .login-link:hover {
            text-decoration: underline;
        }

    </style>

</head>

<body>

<?php
require_once __DIR__
    . '/../components/header.php';
?>

<main class="register-container">

    <div class="register-title">

        <h1>
            회원가입
        </h1>

        <p>
            시민의소리 서비스 이용을 위해
            회원정보를 입력해주세요.
        </p>

    </div>


    <div class="register-box">

        <?php if (isset($error)): ?>

            <div class="error">
                <?= htmlspecialchars($error) ?>
            </div>

        <?php endif; ?>


        <form method="post">

            <div class="form-group">

                <label for="id">
                    아이디
                </label>

                <input
                    type="text"
                    id="id"
                    name="id"
                    placeholder="아이디를 입력해주세요."
                    required
                >

            </div>


            <div class="form-group">

                <label for="pw">
                    비밀번호
                </label>

                <input
                    type="password"
                    id="pw"
                    name="pw"
                    placeholder="비밀번호를 입력해주세요."
                    required
                >

            </div>


            <div class="form-group">

                <label for="name">
                    이름
                </label>

                <input
                    type="text"
                    id="name"
                    name="name"
                    placeholder="이름을 입력해주세요."
                    required
                >

            </div>


            <button
                type="submit"
                class="register-btn"
            >
                회원가입
            </button>

        </form>


        <div class="login-area">

            <span>
                이미 회원이신가요?
            </span>

            <a
                href="/auth/login.php"
                class="login-link"
            >
                로그인
            </a>

        </div>

    </div>

</main>

</body>

</html>