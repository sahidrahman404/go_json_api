create table if not exists tokens ( 
    hash bytea PRIMARY KEY,
    user_id bigint not null references users on delete cascade,
    expiry timestamp(0) with time zone not null,
    scope text not null
);
