<?php

require_once __DIR__ . '/../db.php';

$sql = "
    SELECT
        id,
        title,
        status,
        created_at
    FROM inquiry
    WHERE visibility = 'PUBLIC'
    ORDER BY id DESC
    LIMIT 5
";

$result = $pdo->query($sql);

$recentInquiries = $result->fetchAll(PDO::FETCH_ASSOC);