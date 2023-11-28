CREATE TABLE owner_vouchers (
    guid varchar(36) NOT NULL PRIMARY KEY,
    contents blob NOT NULL,
    to2_performed bool,
    to0_accept_owner_wait_seconds bigint
);
