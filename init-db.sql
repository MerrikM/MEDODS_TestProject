CREATE TABLE IF NOT EXISTS refresh_tokens (
    uuid       uuid      not null
    primary key,
    user_uuid  uuid      not null,
    token_hash text      not null,
    expire_at  timestamp not null,
    used       boolean default false,
    user_agent text,
    ip_address text
);