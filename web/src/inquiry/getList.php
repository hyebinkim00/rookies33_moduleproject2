<?php

require_once __DIR__ . '/../db.php';


$type = $_GET['type'] ?? 'title';
$keyword = $_GET['keyword'] ?? '';

$sql = "
    SELECT
        i.id,
        i.title,
        i.status,
        i.created_at,
        u.name
    FROM inquiry i
    JOIN users u ON i.user_id = u.id
    WHERE i.visibility = 'PUBLIC'
";

if ($keyword !== '') {

    if ($type === 'content') {

        $sql .= " AND i.content LIKE '%" . $keyword . "%' ";

    } elseif ($type === 'title_content') {

        $sql .= "
            AND (
                i.title LIKE '%" . $keyword . "%'
                OR i.content LIKE '%" . $keyword . "%'
            )
        ";

    } else {

        $sql .= " AND i.title LIKE '%" . $keyword . "%' ";
    }
}

$sql .= " ORDER BY i.id DESC ";


$result = $pdo->query($sql);
$inquiries = $result->fetchAll(PDO::FETCH_ASSOC);