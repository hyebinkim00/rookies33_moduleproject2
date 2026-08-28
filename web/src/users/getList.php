<?php require_once __DIR__ . '/../db.php';
/* 관리자 확인 */

/* 회원 목록 조회 */
$sql = " SELECT id, login_id, name, role, created_at FROM users ORDER BY id ASC ";

$stmt = $pdo->query($sql);
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

