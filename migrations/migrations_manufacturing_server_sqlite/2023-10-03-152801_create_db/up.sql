CREATE TABLE manufacturer_vouchers (
    guid varchar(36) NOT NULL PRIMARY KEY,
    contents blob NOT NULL,
    ttl bigint
);
