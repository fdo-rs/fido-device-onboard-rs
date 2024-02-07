diesel::table! {
    manufacturer_vouchers (guid) {
        guid -> Text,
        contents -> Binary,
        ttl -> Nullable<BigInt>,
    }
}

diesel::table! {
    owner_vouchers (guid) {
        guid -> Text,
        contents -> Binary,
        to2_performed -> Nullable<Bool>,
        to0_accept_owner_wait_seconds -> Nullable<BigInt>,
    }
}

diesel::table! {
    rendezvous_vouchers (guid) {
        guid -> Text,
        contents -> Binary,
        ttl -> Nullable<BigInt>,
    }
}
