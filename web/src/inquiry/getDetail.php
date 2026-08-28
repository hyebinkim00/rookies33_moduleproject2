<?php

require_once __DIR__ . '/../db.php';

$id = $_GET['id'] ?? 0;

/* 민원 상세 조회 */
$sql = "
    SELECT
        i.id,
        i.user_id,
        i.title,
        i.content,
        i.visibility,
        i.status,
        i.answer,
        i.answered_by,
        i.answered_at,
        i.created_at,

        u.name AS user_name,
        au.name AS answer_user_name

    FROM inquiry i

    JOIN users u
        ON i.user_id = u.id

    LEFT JOIN users au
        ON i.answered_by = au.id

    WHERE i.id = $id
";
$result = $pdo->query($sql);

$inquiry = $result->fetch(PDO::FETCH_ASSOC);

if (!$inquiry) {
    exit('존재하지 않는 민원입니다.');
}


/* 첨부파일 목록 조회 */
$fileSql = "
    SELECT
        id,
        original_filename,
        stored_filename,
        file_path,
        created_at
    FROM inquiry_file
    WHERE inquiry_id = $id
    ORDER BY id ASC
";

$fileResult = $pdo->query($fileSql);

$inquiryFiles = $fileResult->fetchAll(PDO::FETCH_ASSOC);