<?php

require_once __DIR__ . '/../db.php';

/* 게시글 삭제 */

if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['delete_inquiry'])) {

    $id = (int)$_POST['delete_inquiry'];

    if ($id <= 0) {
        echo "<script>
            alert('잘못된 요청입니다.');
            history.back();
        </script>";
        exit;
    }

    $sql = "DELETE FROM inquiry WHERE id = :id";

    $stmt = $pdo->prepare($sql);

    $stmt->execute([
        ':id' => $id
    ]);

    echo "<script>
        alert('게시글이 삭제되었습니다.');
        location.href='/admin/admin.php';
    </script>";

    exit;
}