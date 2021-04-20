use super::PgpAgent;

const API_ENDPOINT: &'static str = "https://sdkms.test.fortanix.com";
const MY_API_KEY: &'static str = "YjI1Y2M4NzUtZTNhOC00MmE5LTk1OWYtOGI0N2IyMDE2OWFmOnl4TThQWWdhclBWVzhQajRBZkVZcUNYM292TUVRVkRYbWh2d1V2OUxLeTB0UDY4eTFJZld2TlJFbmZTckxGdHIwZ25NVk9NMlhWTmZEalNSX3VzRVZB";

#[test]
#[ignore = "generates a key in SDKMS"]
fn generate() {
    PgpAgent::generate_key(
        Some(API_ENDPOINT.to_string()),
        MY_API_KEY.to_string(),
        "Test"
    ).unwrap();
}

#[test]
fn armored_public_key() {
    let mut agent = PgpAgent::from_key_name(
        Some(API_ENDPOINT.to_string()),
        MY_API_KEY.to_string(),
        "Test").unwrap();

    let armored = agent.get_armored_key().unwrap();

    assert_eq!(&armored[..36], "-----BEGIN PGP PUBLIC KEY BLOCK-----".as_bytes());

    // {
    //     use std::io::{self, Write};
    //     let stdout = io::stdout();
    //     let mut handle = stdout.lock();

    //     handle.write_all(&armored).unwrap();
    // }
}
