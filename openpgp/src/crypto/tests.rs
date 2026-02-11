//! Low-level crypto tests.

mod rsa;
mod dsa;
mod ecdsa;

#[test]
fn raw_bigint_cmp() {
    use std::cmp::Ordering;
    use crate::crypto::raw_bigint_cmp as cmp;

    assert_eq!(cmp(&[], &[]), Ordering::Equal);
    assert_eq!(cmp(&[], &[1]), Ordering::Less);
    assert_eq!(cmp(&[1], &[]), Ordering::Greater);
    assert_eq!(cmp(&[1], &[1]), Ordering::Equal);
    assert_eq!(cmp(&[1], &[2]), Ordering::Less);
    assert_eq!(cmp(&[2], &[1]), Ordering::Greater);
    assert_eq!(cmp(&[1], &[1, 2]), Ordering::Less);
    assert_eq!(cmp(&[1, 2], &[1]), Ordering::Greater);
    assert_eq!(cmp(&[1], &[2, 1]), Ordering::Less);
    assert_eq!(cmp(&[2, 1], &[1]), Ordering::Greater);

    assert_eq!(cmp(&[0], &[]), Ordering::Equal);
    assert_eq!(cmp(&[0], &[1]), Ordering::Less);
    assert_eq!(cmp(&[0, 1], &[]), Ordering::Greater);

    assert_eq!(cmp(&[], &[0]), Ordering::Equal);
    assert_eq!(cmp(&[], &[0, 1]), Ordering::Less);
    assert_eq!(cmp(&[1], &[0]), Ordering::Greater);
}
