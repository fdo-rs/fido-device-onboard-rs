#[cfg(test)]
mod tests {
    use std::io::BufRead;

    const CAVP_PRINT_PASS: Option<&'static str> = option_env!("CAVP_PRINT_PASS");
    const CAVP_PRINT_SKIP: Option<&'static str> = option_env!("CAVP_PRINT_SKIP");
    const CAVP_REQUIRE_ALL: Option<&'static str> = option_env!("CAVP_REQUIRE_ALL");
    const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[allow(unused_imports)]
    use crate::{KdfArgument, KdfError, KdfKbMode, KdfMacType, KdfType};
    #[allow(unused_imports)]
    use openssl::{hash::MessageDigest, nid::Nid, symm::Cipher};

    fn cavp_tests_that_should_pass() -> u64 {
        let mut num_that_should_pass = 0;

        #[cfg(implementation = "ossl11")]
        {
            const CAVP_SHOULD_PASS_OSSL11: u64 = 0;
            num_that_should_pass = std::cmp::max(num_that_should_pass, CAVP_SHOULD_PASS_OSSL11);
        }
        #[cfg(implementation = "ossl3")]
        {
            #[cfg(not(ossl3_supported = "kbkdf_r"))]
            const CAVP_SHOULD_PASS_OSSL3: u64 = 320;
            #[cfg(ossl3_supported = "kbkdf_r")]
            const CAVP_SHOULD_PASS_OSSL3: u64 = 1280;
            num_that_should_pass = std::cmp::max(num_that_should_pass, CAVP_SHOULD_PASS_OSSL3);
        }
        #[cfg(implementation = "custom")]
        {
            const CAVP_SHOULD_PASS_CUSTOM: u64 = 1280;
            num_that_should_pass = std::cmp::max(num_that_should_pass, CAVP_SHOULD_PASS_CUSTOM);
        }
        #[cfg(all(implementation = "ossl3", implementation = "custom"))]
        {
            const CAVP_SHOULD_PASS_CUSTOM_AND_OSSL3: u64 = 960;
            num_that_should_pass =
                std::cmp::max(num_that_should_pass, CAVP_SHOULD_PASS_CUSTOM_AND_OSSL3);
        }

        num_that_should_pass
    }

    fn parse_kv(line: &str) -> (&str, &str) {
        let line = if line.starts_with("[") {
            line[1..line.len() - 1].trim()
        } else {
            line
        };
        let (key, value) = line.split_once('=').unwrap();
        (key.trim(), value.trim())
    }

    fn cmac_to_cipher(value: &str) -> Cipher {
        match value {
            "AES128" => Cipher::aes_128_cbc(),
            "AES192" => Cipher::aes_192_cbc(),
            "AES256" => Cipher::aes_256_cbc(),
            _ => panic!("Unsupported CMAC cipher: {}", value),
        }
    }

    fn hmac_to_md(value: &str) -> MessageDigest {
        match value {
            "SHA1" => MessageDigest::sha1(),
            "SHA224" => MessageDigest::sha224(),
            "SHA256" => MessageDigest::sha256(),
            "SHA384" => MessageDigest::sha384(),
            "SHA512" => MessageDigest::sha512(),
            _ => panic!("Unsupported HMAC digest: {}", value),
        }
    }

    #[test]
    fn cavp_kbkdf_counter_mode() {
        let input_file = std::path::PathBuf::from(&MANIFEST_DIR).join("test_assets/KDFCTR_gen.rsp");
        let input_file = std::fs::File::open(input_file).unwrap();
        let reader = std::io::BufReader::new(input_file).lines();

        let mut num_executed = 0;
        let mut num_passed = 0;
        let mut num_skipped = 0;
        let mut num_failed = 0;

        let mut mac: Option<KdfMacType> = None;
        let mut skip_prf = false;
        let mut correct_ctrlocation = false;
        let mut rlen: Option<u8> = None;
        let mut count: Option<u64> = None;
        let mut len: Option<usize> = None;
        let mut ki: Option<Vec<u8>> = None;
        let mut fixed_input: Option<Vec<u8>> = None;

        for line in reader {
            let line = line.unwrap();
            let line = line.trim();
            if line.len() == 0 || line.starts_with("#") {
                continue;
            }
            let (key, value) = parse_kv(&line);
            if key != "PRF" && skip_prf {
                continue;
            }
            if (key != "PRF" && key != "CTRLOCATION") && !correct_ctrlocation {
                continue;
            }
            let expected = match key {
                "PRF" => {
                    skip_prf = false;
                    let (prf_type, prf_name) = value.split_once('_').unwrap();
                    match prf_type {
                        "CMAC" => match prf_name {
                            "TDES2" | "TDES3" => skip_prf = true,
                            name => mac = Some(KdfMacType::Cmac(cmac_to_cipher(name))),
                        },
                        "HMAC" => mac = Some(KdfMacType::Hmac(hmac_to_md(prf_name))),
                        _ => panic!("unknown PRF type: {}", prf_type),
                    }
                    continue;
                }
                "CTRLOCATION" => {
                    correct_ctrlocation = value == "BEFORE_FIXED";
                    continue;
                }
                "RLEN" => {
                    rlen = Some(match value {
                        "8_BITS" => 8,
                        "16_BITS" => 16,
                        "24_BITS" => 24,
                        "32_BITS" => 32,
                        _ => panic!("unsupported rlen: {}", value),
                    });
                    continue;
                }
                "COUNT" => {
                    count = Some(value.parse::<u64>().unwrap());
                    continue;
                }
                "L" => {
                    len = Some(value.parse::<usize>().unwrap());
                    continue;
                }
                "KI" => {
                    ki = Some(hex::decode(value).unwrap());
                    continue;
                }
                "FixedInputDataByteLen" => {
                    continue;
                }
                "FixedInputData" => {
                    fixed_input = Some(hex::decode(value).unwrap());
                    continue;
                }
                "KO" => {
                    hex::decode(value).unwrap()
                    // Not continuing, we have the info to execute this test case
                }
                _ => panic!("Unknown CAVP file key: {}", key),
            };
            num_executed += 1;
            let mac = mac.unwrap();
            let fixed_input = fixed_input.as_ref().unwrap();
            let ki = ki.as_ref().unwrap();
            let rlen = rlen.unwrap();
            let len = len.unwrap();
            let print_descrip = || {
                eprintln!("\tExecuting CAVP case, prf: {:?}, ctrlocation: {:?}, rlen: {:?}, count: {:?}, len: {:?}, ki: {:?}, fixed_input: {:?}, expected: {:?}", mac, correct_ctrlocation, rlen, count, len, ki, fixed_input, expected)
            };

            let mac_arg = KdfArgument::Mac(mac);
            let fixed_input_arg = KdfArgument::Salt(fixed_input);
            let ki_arg = KdfArgument::Key(ki);
            let rlen_arg = KdfArgument::R(rlen);

            let mut args = vec![
                &KdfArgument::KbMode(KdfKbMode::Counter),
                &mac_arg,
                &fixed_input_arg,
                &ki_arg,
                &KdfArgument::UseSeparator(false),
                &KdfArgument::UseL(false),
            ];
            if rlen != 32 {
                args.push(&rlen_arg);
            }
            if !crate::supports_args(&args) {
                if CAVP_PRINT_SKIP.is_some() {
                    print_descrip();
                    eprintln!("\tSKIPPED, unsupported by this backend");
                }
                num_skipped += 1;
                continue;
            }
            let key_out = crate::perform_kdf(KdfType::KeyBased, &args, len / 8);
            match key_out {
                Ok(key) => {
                    if key == expected {
                        if CAVP_PRINT_PASS.is_some() {
                            print_descrip();
                            eprintln!("\t\tPASSED");
                        }
                        num_passed += 1;
                    } else {
                        print_descrip();
                        eprintln!("\t\tFAILED, expected: {:?}, got: {:?}", expected, key);
                        num_failed += 1;
                    }
                }
                Err(e) => {
                    print_descrip();
                    eprintln!("\t\tFAILED, error: {:?}", e);
                    num_failed += 1;
                }
            }
        }

        let should_pass = cavp_tests_that_should_pass();

        eprintln!("CAVP results:");
        eprintln!("\tExecuted: {}", num_executed);
        eprintln!("\tPassed: {} (should be: {})", num_passed, should_pass);
        eprintln!("\tSkipped: {}", num_skipped);
        eprintln!("\tFailed: {}", num_failed);

        if num_failed > 0 {
            panic!("One or more tests failed");
        }
        if num_skipped > 0 && CAVP_REQUIRE_ALL.is_some() {
            panic!("One or more tests skipped");
        }
        if num_passed != should_pass {
            panic!("Not the correct number of tests passed");
        }
    }

    #[test]
    fn hmac_sha256_test() {
        let deadbeef = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let args = [
            &KdfArgument::KbMode(KdfKbMode::Counter),
            &KdfArgument::Mac(KdfMacType::Hmac(MessageDigest::sha256())),
            &KdfArgument::Salt(&deadbeef),
            &KdfArgument::Key(&deadbeef),
            &KdfArgument::KbInfo(&deadbeef),
        ];

        let key_out = crate::perform_kdf(KdfType::KeyBased, &args, 20).unwrap();

        assert_eq!(
            key_out,
            vec![
                0x76, 0xF4, 0x63, 0xE2, 0xDF, 0x22, 0xD3, 0xDE, 0x02, 0xFD, 0x02, 0xCA, 0x59, 0x58,
                0x16, 0xBD, 0xCE, 0x3D, 0x19, 0xB0
            ],
        );
    }

    // Tests from OpenSSL 1.1
    #[cfg(any(implementation = "ossl11", implementation = "ossl3"))]
    #[test]
    fn test_kdf_kbkdf_6803_128() {
        let input_key: [u8; 16] = [
            0x57, 0xD0, 0x29, 0x72, 0x98, 0xFF, 0xD9, 0xD3, 0x5D, 0xE5, 0xA4, 0x7F, 0xB4, 0xBD,
            0xE2, 0x4B,
        ];
        let iv: [u8; 16] = [0; 16];
        let in_out: [([u8; 5], [u8; 16]); 3] = [
            (
                [0x00, 0x00, 0x00, 0x02, 0x99],
                [
                    0xD1, 0x55, 0x77, 0x5A, 0x20, 0x9D, 0x05, 0xF0, 0x2B, 0x38, 0xD4, 0x2A, 0x38,
                    0x9E, 0x5A, 0x56,
                ],
            ),
            (
                [0x00, 0x00, 0x00, 0x02, 0xaa],
                [
                    0x64, 0xDF, 0x83, 0xF8, 0x5A, 0x53, 0x2F, 0x17, 0x57, 0x7D, 0x8C, 0x37, 0x03,
                    0x57, 0x96, 0xAB,
                ],
            ),
            (
                [0x00, 0x00, 0x00, 0x02, 0x55],
                [
                    0x3E, 0x4F, 0xBD, 0xF3, 0x0F, 0xB8, 0x25, 0x9C, 0x42, 0x5C, 0xB6, 0xC9, 0x6F,
                    0x1F, 0x46, 0x35,
                ],
            ),
        ];

        for (constant, output) in in_out {
            let args = [
                &KdfArgument::KbMode(KdfKbMode::Feedback),
                &KdfArgument::Mac(KdfMacType::Cmac(
                    Cipher::from_nid(Nid::CAMELLIA_128_CBC).unwrap(),
                )),
                &KdfArgument::Key(&input_key),
                &KdfArgument::Salt(&constant),
                &KdfArgument::KbSeed(&iv),
            ];

            let key_out = crate::perform_kdf(KdfType::KeyBased, &args, 16).unwrap();

            assert_eq!(key_out, output,);
        }
    }
}
