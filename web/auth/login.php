<?php

session_start();

require_once __DIR__ . '/../src/db.php';

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $login_id = $_POST["id"] ?? "";
    $login_pw = $_POST["pw"] ?? "";

    try {

        $stmt = $pdo->prepare(
            "SELECT * FROM users WHERE login_id = '$login_id'"
        );

        $stmt->execute();

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (
            $user &&
            password_verify($login_pw, $user["password"])
        ) {

            $_SESSION["user_id"] = $user["id"];
            $_SESSION["user"] = $user["login_id"];
            $_SESSION["name"] = $user["name"];
            $_SESSION["role"] = $user["role"];

            if ($_SESSION["role"] === "ADMIN") {
                header("Location: /admin/admin.php");
                exit;
            }

            header("Location: /");
            exit;

        } else {

            $error = "아이디 또는 비밀번호가 틀렸습니다.";
        }

    } catch (PDOException $e) {

        $error = "로그인 중 오류가 발생했습니다.";
    }
}

?>

<!DOCTYPE html>
<html lang="ko">

<head>
    <link
        rel="stylesheet"
        href="/assets/css/common.css"
    >

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>로그인 | 시민의소리</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, "Noto Sans KR", sans-serif;
            color: #222;
            background: #f5f7fa;
        }



        /* 로그인 영역 */

        .login-container {
            width: 430px;
            margin: 80px auto;
        }

        .login-title {
            margin-bottom: 30px;
            text-align: center;
        }

        .login-title h1 {
            margin: 0 0 10px;
            color: #343a72;
            font-size: 28px;
        }

        .login-title p {
            margin: 0;
            color: #777;
            font-size: 14px;
        }

        .login-box {
            padding: 35px 40px 40px;
            background: #fff;
            border: 1px solid #dfe3e8;
        }

        /* 입력 */

        .form-group {
            margin-bottom: 15px;
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

        /* 오류 */

        .error {
            margin: 0 0 18px;
            padding: 11px 13px;

            background: #fff3f3;
            border: 1px solid #f0cccc;

            color: #c0392b;
            font-size: 13px;
        }

        /* 버튼 */

        .login-btn {
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

        .login-btn:hover {
            background: #272c5d;
        }

        .register-area {
            margin-top: 18px;
            padding-top: 18px;

            border-top: 1px solid #eee;

            text-align: center;
        }

        .register-area span {
            color: #777;
            font-size: 13px;
        }

        .register-link {
            margin-left: 8px;

            color: #343a72;
            font-size: 13px;
            font-weight: bold;
            text-decoration: none;
        }

        .register-link:hover {
            text-decoration: underline;
        }

        /* 홈 */

        .home-link {
            margin-top: 20px;
            text-align: center;
        }

        .home-link a {
            color: #777;
            font-size: 13px;
            text-decoration: none;
        }

        .home-link a:hover {
            color: #343a72;
        }

    </style>

</head>

<body>

<?php require_once __DIR__ . '/../components/header.php'; ?>

<main class="login-container">

    <div class="login-title">
        <h1>로그인</h1>
        <p>
            시민의소리 서비스를 이용하려면 로그인해주세요.
        </p>
    </div>

    <div class="login-box">

        <?php if (isset($error)): ?>
            <div class="error">
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <form method="post">

            <div class="form-group">
                <label for="id">아이디</label>

                <input
                    type="text"
                    id="id"
                    name="id"
                    placeholder="아이디를 입력해주세요."
                    required
                >
            </div>

            <div class="form-group">
                <label for="pw">비밀번호</label>

                <input
                    type="password"
                    id="pw"
                    name="pw"
                    placeholder="비밀번호를 입력해주세요."
                    required
                >
            </div>

            <button type="submit" class="login-btn">
                로그인
            </button>

        </form>

        <div class="register-area">
            <span>아직 회원이 아니신가요?</span>

            <a href="/auth/register.php" class="register-link">
                회원가입
            </a>
        </div>

    </div>

</main>

</body>

</html>