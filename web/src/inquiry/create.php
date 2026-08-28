<?php

session_start();

require_once __DIR__ . '/../db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    exit('잘못된 요청입니다.');
}

if (!isset($_SESSION['user_id'])) {
    echo "<script>
        alert('로그인이 필요합니다.');
        location.href = '/auth/login.php';
    </script>";
    exit;
}

$title = $_POST['title'] ?? '';
$content = $_POST['content'] ?? '';
$visibility = $_POST['visibility'] ?? 'PUBLIC';
$userId = $_SESSION['user_id'];

$sql = "
    INSERT INTO inquiry (
        user_id,
        title,
        content,
        visibility
    )
    VALUES (
        $userId,
        '$title',
        '$content',
        '$visibility'
    )
";

$pdo->exec($sql);

$inquiryId = $pdo->lastInsertId();

$uploadDir = __DIR__ . '/../../uploads/';

if (
    isset($_FILES['attachments']) &&
    is_array($_FILES['attachments']['name'])
) {

    $fileCount = count($_FILES['attachments']['name']);

    for ($i = 0; $i < $fileCount; $i++) {

        if (
            $_FILES['attachments']['error'][$i]
            !== UPLOAD_ERR_OK
        ) {
            continue;
        }

        $originalFilename =
            basename($_FILES['attachments']['name'][$i]);

        $tmpName =
            $_FILES['attachments']['tmp_name'][$i];

        $storedFilename = $originalFilename;

        $filePath =
            '/uploads/'
            . $storedFilename;

        if (
            !move_uploaded_file(
                $tmpName,
                $uploadDir . $storedFilename
            )
        ) {
            continue;
        }

        $fileSql = "
            INSERT INTO inquiry_file (
                inquiry_id,
                original_filename,
                stored_filename,
                file_path
            )
            VALUES (
                $inquiryId,
                '$originalFilename',
                '$storedFilename',
                '$filePath'
            )
        ";

        $pdo->exec($fileSql);
    }
}

header('Location: /inquiry/list.php');
exit;