<?php require_once __DIR__ . '/../db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['delete_user'])) {

    $id = (int)$_POST['delete_user'];

    $sql = "DELETE FROM users WHERE id = :id";

    $stmt = $pdo->prepare($sql);

    $stmt->execute([
        ':id' => $id
    ]);

    echo "<script>
        alert('회원이 삭제되었습니다.');
        location.href='/admin/admin.php';
    </script>";

    exit;
}