-- 데이터베이스 스키마 정의 파일
-- users: 유저 테이블
-- inquiry: 문의 게시판
-- inquiry_file: 문의 첨부파일

CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    login_id VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(50) NOT NULL,
    role ENUM('USER', 'ADMIN') NOT NULL DEFAULT 'USER',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;


CREATE TABLE inquiry (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,

    title VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,

    answer TEXT NULL,
    answered_by BIGINT NULL,
    answered_at DATETIME NULL,

    visibility ENUM('PUBLIC', 'PRIVATE')
        NOT NULL DEFAULT 'PUBLIC',

    status ENUM('RECEIVED', 'COMPLETED')
        NOT NULL DEFAULT 'RECEIVED',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    FOREIGN KEY (answered_by)
        REFERENCES users(id)
)
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;


CREATE TABLE inquiry_file (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    inquiry_id BIGINT NOT NULL,

    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (inquiry_id)
        REFERENCES inquiry(id)
        ON DELETE CASCADE
)
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;