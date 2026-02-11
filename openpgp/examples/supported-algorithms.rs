//! This example prints all algorithms supported by the currently
//! selected cryptographic backend.

use sequoia_openpgp as openpgp;
use openpgp::types::*;
use openpgp::cert::CipherSuite;

fn main() {
    println!("Cipher suites:");
    for a in CipherSuite::variants() {
        println!(" - {:70} {:?}", format!("{:?}", a), a.is_supported().is_ok());
    }
    println!();

    println!("Public-Key algorithms:");
    for a in PublicKeyAlgorithm::variants() {
        println!(" - {:70} {:?}", a.to_string(), a.is_supported());
    }
    println!();

    println!("ECC algorithms:");
    for a in Curve::variants() {
        println!(" - {:70} {:?}", a.to_string(), a.is_supported());
    }
    println!();

    println!("Symmetric algorithms:");
    for a in SymmetricAlgorithm::variants() {
        println!(" - {:70} {:?}", a.to_string(), a.is_supported());
    }
    println!();

    println!("AEAD algorithms:");
    for a in AEADAlgorithm::variants() {
        println!(" - {:70} {:?}", a.to_string(), a.is_supported());
    }
    println!();

    println!("Hash algorithms:");
    for a in HashAlgorithm::variants() {
        println!(" - {:70} {:?}", a.to_string(), a.is_supported());
    }
    println!();

    println!("Compression algorithms:");
    for a in CompressionAlgorithm::variants().skip(1) {
        println!(" - {:70} {:?}", a.to_string(), a.is_supported());
    }
    println!();
}
