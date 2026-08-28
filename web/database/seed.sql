-- 데이터베이스 초기 데이터 구성
-- 어드민 계정, 테스트 계정 생성

-- 어드민 1명 유저 6명 테스트 데이터 생성
INSERT INTO users (login_id, password, name, role)
VALUES ('admin', '$2y$12$WWNbeHI4PZWTVaAZG3hHQ.SvNDSAF0mhWFRGF8aUOmAnknlOpfM7S', '관리자', 'ADMIN');

INSERT INTO users (login_id, password, name, role)
VALUES ('user01', '$2y$12$kePHsgQy..x4PFz6fsv7d.nUKlfimu/jZ7G9cbM5niPZnM8p.C2Gi', '김도율', 'USER');

INSERT INTO users (login_id, password, name, role)
VALUES ('user02', '$2y$12$dnFXZiMMopcgqKWIJxOXteEFJuCunv6t9JsEMZbshEexGIazN97qe', '김문선', 'USER');

INSERT INTO users (login_id, password, name, role)
VALUES ('user03', '$2y$12$7PC4yhPyln01vwAveO9DIOeIgPEsvvpw..OjXTHUEYw1J5MuS06De', '김혜빈', 'USER');

INSERT INTO users (login_id, password, name, role)
VALUES ('user04', '$2y$12$srTiviW/g5ROreIec/V.ge6UPJrpRfcttnwtglMwo7WCv055/hq4q', '신선빈', 'USER');

INSERT INTO users (login_id, password, name, role)
VALUES ('user05', '$2y$12$6o/RcHtUEqHVAZji5OIZjuc7cVn/Tm2gQgmuQ9S4oFwmLK4.xBss.', '오승준', 'USER');

INSERT INTO users (login_id, password, name, role)
VALUES ('user06', '$2y$12$KOKAeolwzCfqv6kDzb1uVeG0HpukGRAjrNIs3LA9HpLviwDxcPskW', '이우진', 'USER');


-- =========================================
-- 민원 테스트 데이터 생성
-- admin  : id = 1
-- user01 : id = 2
-- user02 : id = 3
-- user03 : id = 4
-- user04 : id = 5
-- user05 : id = 6
-- user06 : id = 7
-- =========================================


-- 1. user01 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    2,
    '주택가 불법 주정차 단속 요청',
    '주택가 골목에 불법 주정차 차량이 많아 통행에 불편이 있습니다. 단속을 요청드립니다.',
    'PUBLIC',
    'RECEIVED'
);


-- 2. user02 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    3,
    '공원 내 운동기구 점검 요청',
    '동네 공원에 설치된 운동기구 일부가 파손되어 있습니다. 안전사고 예방을 위해 점검 부탁드립니다.',
    'PUBLIC',
    'RECEIVED'
);


-- 3. user03 / 답변완료
INSERT INTO inquiry (
    user_id,
    title,
    content,
    answer,
    answered_by,
    answered_at,
    visibility,
    status
)
VALUES (
    4,
    '가로등 고장 신고',
    '주택가 도로의 가로등이 며칠째 켜지지 않고 있습니다. 야간 통행 시 위험하니 확인 부탁드립니다.',
    '신고해주신 위치의 가로등을 현장 점검하였으며, 고장 난 부품을 교체하여 현재 정상적으로 작동하고 있습니다.',
    1,
    NOW(),
    'PUBLIC',
    'COMPLETED'
);


-- 4. user04 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    5,
    '쓰레기 무단투기 관련 문의',
    '최근 골목길에 쓰레기 무단투기가 반복되고 있습니다. 관련 단속이나 신고 방법을 알고 싶습니다.',
    'PUBLIC',
    'RECEIVED'
);


-- 5. user05 / 답변완료
INSERT INTO inquiry (
    user_id,
    title,
    content,
    answer,
    answered_by,
    answered_at,
    visibility,
    status
)
VALUES (
    6,
    '도로 파손 보수 요청',
    '도로 일부가 파손되어 차량 통행 시 불편이 발생하고 있습니다. 현장 확인 후 보수 부탁드립니다.',
    '접수해주신 도로 파손 구간을 확인하였으며, 해당 구간의 긴급 보수 작업을 완료하였습니다. 제보해주셔서 감사합니다.',
    1,
    NOW(),
    'PUBLIC',
    'COMPLETED'
);


-- 6. user06 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    7,
    '버스 정류장 시설 개선 요청',
    '버스 정류장 의자가 파손되어 이용이 어렵습니다. 시설물 점검 및 교체를 요청드립니다.',
    'PUBLIC',
    'RECEIVED'
);


-- 7. user01 / 비공개 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    2,
    '이전 민원 처리 결과 관련 문의',
    '이전에 신청한 민원의 처리 결과와 관련하여 추가로 확인하고 싶은 사항이 있습니다.',
    'PRIVATE',
    'RECEIVED'
);


-- 8. user02 / 답변완료
INSERT INTO inquiry (
    user_id,
    title,
    content,
    answer,
    answered_by,
    answered_at,
    visibility,
    status
)
VALUES (
    3,
    '공공 체육시설 이용시간 문의',
    '주말 공공 체육시설 운영시간과 이용 신청 방법에 대해 문의드립니다.',
    '공공 체육시설은 주말에도 운영되며 시설별 운영시간이 다를 수 있습니다. 이용 전 해당 시설의 운영시간을 확인해주시기 바랍니다.',
    1,
    NOW(),
    'PUBLIC',
    'COMPLETED'
);


-- 9. user03 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    4,
    '보행로 자전거 통행 관련 요청',
    '보행자 전용 구역에서 자전거 통행이 많아 사고 위험이 있습니다. 안내 표지 설치를 검토해주세요.',
    'PUBLIC',
    'RECEIVED'
);


-- 10. user04 / 비공개 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    5,
    '개인 민원 상담 요청',
    '개인적인 민원 사항과 관련하여 담당 부서의 상담을 요청드립니다.',
    'PRIVATE',
    'RECEIVED'
);


-- 11. user05 / 답변완료
INSERT INTO inquiry (
    user_id,
    title,
    content,
    answer,
    answered_by,
    answered_at,
    visibility,
    status
)
VALUES (
    6,
    '공공 와이파이 연결 불량 신고',
    '공원에 설치된 공공 와이파이가 자주 끊기고 연결이 되지 않습니다. 점검 부탁드립니다.',
    '현장 확인 결과 무선 네트워크 장비에 일시적인 장애가 확인되었습니다. 장비 점검 및 재설정을 완료하여 현재 정상적으로 이용할 수 있습니다.',
    1,
    NOW(),
    'PUBLIC',
    'COMPLETED'
);


-- 12. user06 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    7,
    '횡단보도 신호시간 조정 요청',
    '어르신들이 횡단보도를 건너기에 보행 신호 시간이 짧은 것 같습니다. 신호시간 검토를 요청드립니다.',
    'PUBLIC',
    'RECEIVED'
);


-- 13. user01 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    2,
    '공원 야간 소음 문제',
    '늦은 시간 공원 이용객으로 인한 소음이 지속되고 있습니다. 관련 안내나 관리가 필요해 보입니다.',
    'PUBLIC',
    'RECEIVED'
);


-- 14. user02 / 답변완료
INSERT INTO inquiry (
    user_id,
    title,
    content,
    answer,
    answered_by,
    answered_at,
    visibility,
    status
)
VALUES (
    3,
    '분리수거함 추가 설치 요청',
    '주민 이용이 많은 장소에 분리수거함이 부족합니다. 추가 설치를 검토해주시기 바랍니다.',
    '요청하신 지역의 이용 현황을 확인하였으며, 주민 편의를 위해 분리수거함을 추가 설치하였습니다.',
    1,
    NOW(),
    'PUBLIC',
    'COMPLETED'
);


-- 15. user03 / 비공개 / 답변완료
INSERT INTO inquiry (
    user_id,
    title,
    content,
    answer,
    answered_by,
    answered_at,
    visibility,
    status
)
VALUES (
    4,
    '민원 신청 내용 수정 문의',
    '신청한 민원의 내용을 일부 잘못 작성했습니다. 접수 이후 수정할 수 있는지 문의드립니다.',
    '현재 접수 완료된 민원은 직접 수정할 수 없습니다. 필요한 경우 새로운 민원을 작성하여 정확한 내용을 전달해주시기 바랍니다.',
    1,
    NOW(),
    'PRIVATE',
    'COMPLETED'
);


-- 16. user04 / 답변완료
INSERT INTO inquiry (
    user_id,
    title,
    content,
    answer,
    answered_by,
    answered_at,
    visibility,
    status
)
VALUES (
    5,
    '어린이 보호구역 안전시설 요청',
    '학교 앞 어린이 보호구역에 차량 속도가 빠른 경우가 많습니다. 안전시설 보강을 요청드립니다.',
    '현장 안전시설을 점검하였으며 어린이 보호구역 안내 표지와 노면 표시 상태를 확인했습니다. 추가 안전시설 설치 여부도 검토하겠습니다.',
    1,
    NOW(),
    'PUBLIC',
    'COMPLETED'
);


-- 17. user05 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    6,
    '공용 화장실 청결 관리 요청',
    '공원 공용 화장실의 청결 상태가 좋지 않습니다. 주기적인 관리와 점검을 부탁드립니다.',
    'PUBLIC',
    'RECEIVED'
);


-- 18. user06 / 답변완료
INSERT INTO inquiry (
    user_id,
    title,
    content,
    answer,
    answered_by,
    answered_at,
    visibility,
    status
)
VALUES (
    7,
    '주민센터 운영시간 문의',
    '평일 업무시간 이후에도 이용 가능한 주민센터 민원 서비스가 있는지 문의드립니다.',
    '주민센터 일반 민원 업무는 평일 운영시간 내 이용할 수 있습니다. 일부 민원서류는 무인민원발급기를 통해 운영시간 외에도 발급할 수 있습니다.',
    1,
    NOW(),
    'PUBLIC',
    'COMPLETED'
);


-- 19. user01 / 비공개 / 답변완료
INSERT INTO inquiry (
    user_id,
    title,
    content,
    answer,
    answered_by,
    answered_at,
    visibility,
    status
)
VALUES (
    2,
    '개인정보 처리 관련 문의',
    '민원 신청 과정에서 입력되는 개인정보의 보관 및 처리 방법에 대해 문의드립니다.',
    '민원 처리 과정에서 수집된 정보는 민원 확인 및 답변을 위한 목적으로 처리됩니다. 개인정보 처리와 관련된 자세한 사항은 개인정보 처리방침을 확인해주시기 바랍니다.',
    1,
    NOW(),
    'PRIVATE',
    'COMPLETED'
);


-- 20. user02 / 처리중
INSERT INTO inquiry (
    user_id,
    title,
    content,
    visibility,
    status
)
VALUES (
    3,
    '도로변 배수시설 점검 요청',
    '비가 많이 올 때 도로변에 물이 고이는 현상이 반복되고 있습니다. 배수시설 점검을 요청드립니다.',
    'PUBLIC',
    'RECEIVED'
);