<?php

require_once __DIR__ . '/../db.php';

// 세션 및 URL 파라미터 값 가져오기
$userId = $_SESSION['user_id'];
$type = $_GET['type'] ?? 'title';
$keyword = $_GET['keyword'] ?? '';

$sql = "
    SELECT
        id,
        title,
        visibility,
        status,
        created_at
    FROM inquiry
    WHERE user_id = '" . $userId . "'
";

if ($keyword !== '') {

    if ($type === 'content') {

        $sql .= " AND content LIKE '%" . $keyword . "%' ";

    } elseif ($type === 'title_content') {

        $sql .= "
            AND (
                title LIKE '%" . $keyword . "%'
                OR content LIKE '%" . $keyword . "%'
            )
        ";

    } else {

        $sql .= " AND title LIKE '%" . $keyword . "%' ";
    }
}

$sql .= " ORDER BY id DESC";

$result = $pdo->query($sql);
$inquiries = $result->fetchAll(PDO::FETCH_ASSOC);