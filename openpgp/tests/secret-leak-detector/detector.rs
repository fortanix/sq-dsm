//! Scans a process memory for secret leaks.
//!
//! This is the code doing the experiments and scanning itself for
//! leaks.  See ../secret-leak-detector.rs for details.

use std::{
    alloc::{GlobalAlloc, System, Layout},
    backtrace::Backtrace,
    collections::HashMap,
    io::{Read, Write},
    sync::Mutex,
    sync::atomic::AtomicBool,
    sync::atomic::Ordering,
};

use sequoia_openpgp::{
    crypto::{mem, mpi::ProtectedMPI, Password, SessionKey, Signer},
    fmt::hex,
    packet::{
        key::{Key4, PrimaryRole},
        PKESK,
        SKESK,
    },
    serialize::stream::{
        Message, Encryptor, LiteralWriter,
    },
    parse::{
        stream::*,
        Parse,
    },
    policy::StandardPolicy,
    types::{
        HashAlgorithm,
        SymmetricAlgorithm,
    },
    Cert,
    KeyHandle,
    Result,

};

/// An allocator that leaks all allocations making it easier to spot
/// secret leaks.
struct LeakingAllocator;

/// A leak detected at deallocation time.
struct Leak {
    addr: usize,
    size: usize,
    offset: usize,
    backtrace: Backtrace,
}

static LEAKS: Mutex<Vec<Leak>> = Mutex::new(Vec::new());

thread_local!(static IN_DEALLOC: AtomicBool = AtomicBool::new(false));

unsafe impl GlobalAlloc for LeakingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Don't do anything that may result in a deallocation as
        // otherwise we'll recurse.

        if IN_DEALLOC.with(|in_dealloc| in_dealloc.swap(true, Ordering::SeqCst)) {
            // The deallocator is freeing something, which we don't
            // need to scan.  Also, don't risk infinite recursion.
            return;
        }

        let mem = std::slice::from_raw_parts(ptr, layout.size());
        if mem.len() >= NEEDLE.len() {
            for offset in 0..mem.len() - NEEDLE.len() {
                if &mem[offset..offset+NEEDLE.len()] == NEEDLE {
                    let mut leaks = LEAKS.lock().unwrap();
                    leaks.push(Leak {
                        addr: ptr as usize,
                        size: layout.size(),
                        offset,
                        backtrace: std::backtrace::Backtrace::force_capture(),
                    });
                    break;
                }
            }
        }

        IN_DEALLOC.with(|in_dealloc| in_dealloc.store(false, Ordering::SeqCst));
    }
}

#[global_allocator]
static GLOBAL: LeakingAllocator = LeakingAllocator;

/// How often to repeat a test.
const N: usize = 1;

/// The secret to use and scan for.
const NEEDLE: &[u8] = b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
const N0: u8 = NEEDLE[0];

/// A clean base case that does nothing.
fn clean_basecase() {
}

/// Constructs a vector carefully, without leaking the secret during
/// construction.
fn careful_to_vec<B: AsRef<[u8]>>(b: B) -> Vec<u8> {
    let b = b.as_ref();
    let mut r = vec![0; b.len()];
    b.iter().zip(r.iter_mut()).for_each(|(f, t)| *t = *f);
    r
}

/// Checks that a secret has been written.
///
/// Notably, this also prevents optimizing the secret creation away.
fn check_secret(v: &[u8]) {
    assert_eq!(v.iter().cloned().map(usize::from).sum::<usize>(),
               NEEDLE.len() * N0 as usize);
    std::hint::black_box(v); // Avoid optimizing away.
    unsafe {                 // Likewise.
        assert_eq!(libc::memcmp(v.as_ptr() as *const _,
                                NEEDLE.as_ptr() as *const _,
                                NEEDLE.len()), 0);
    }
}

/// A leaky base case that allocates a Vector.
fn leak_basecase() {
    let v = NEEDLE.to_vec();
    check_secret(&v);
}

/// A test case that allocates a Vector and securely overwrites it
/// using [`memsec::memzero`].
fn test_memzero() {
    let mut v = careful_to_vec(NEEDLE);
    check_secret(&v);
    let len = v.len();
    unsafe {
        memsec::memzero(v.as_mut_ptr(), len);
    }
}

/// A test case that allocates a Vector and securely overwrites it
/// using [`libc::memset`].
fn test_libc_memset() {
    let mut v = careful_to_vec(NEEDLE);
    check_secret(&v);
    let len = v.len();
    let p = unsafe {
        libc::memset(v.as_mut_ptr() as _, 0, len)
    };
    std::hint::black_box(p); // Avoid optimizing the memset away.
}

/// A test case that allocates a mem::Protected and drops it.
fn test_protected() {
    let v: mem::Protected = NEEDLE.into();
    check_secret(&v);
    let v: mem::Protected = NEEDLE.to_vec().into();
    check_secret(&v);
}

/// A test case that allocates a mem::Protected and drops it.
fn test_protected_mpi() {
    let v: ProtectedMPI = NEEDLE.to_vec().into_boxed_slice().into();
    check_secret(v.value());
    let v: ProtectedMPI = NEEDLE.to_vec().into();
    check_secret(v.value());
    let v: ProtectedMPI = mem::Protected::from(NEEDLE).into();
    check_secret(v.value());
}

/// A test case that allocates a SessionKey and drops it.
fn test_session_key() {
    let v: SessionKey = NEEDLE.into();
    check_secret(&v);
    let v: SessionKey = NEEDLE.to_vec().into();
    check_secret(&v);
}

/// A test case that allocates a mem::Encrypted, uses it once, then
/// drops it.
fn test_encrypted() {
    let m = mem::Encrypted::new(NEEDLE.into()).unwrap();
    m.map(|v| check_secret(&v));
}

/// A test case that allocates a Password, uses it once, then drops
/// it.
fn test_password() {
    let p = Password::from(NEEDLE);
    p.map(|v| check_secret(&v));
}

/// A test case that allocates a Key4, uses it once, then
/// drops it.
fn test_ed25519() {
    let k = Key4::<_, PrimaryRole>::import_secret_ed25519(NEEDLE, None)
        .unwrap();
    let mut kp = k.into_keypair().unwrap();
    kp.sign(HashAlgorithm::SHA256, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .unwrap();
}

/// A test case that encrypts a message using AES-256.
fn test_aes_256_encryption() {
    aes_256_encryption().unwrap();
}
fn aes_256_encryption() -> Result<Vec<u8>> {
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Encryptor::with_session_key(
        message, SymmetricAlgorithm::AES256, NEEDLE.into())?
        .add_passwords(Some(Password::from(NEEDLE)))
        .build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(b"Hello world.")?;
    w.finalize()?;
    Ok(sink)
}

/// A test case that decrypts a message using AES-256.
fn test_aes_256_decryption() {
    let ciphertext = aes_256_encryption().unwrap();
    aes_256_decryption(&ciphertext).unwrap();
}
fn aes_256_decryption(ciphertext: &[u8]) -> Result<()> {
    let p = &StandardPolicy::new();

    struct Helper {}
    impl VerificationHelper for Helper {
        fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
            Ok(Vec::new())
        }
        fn check(&mut self, _structure: MessageStructure) -> Result<()> {
            Ok(())
        }
    }
    impl DecryptionHelper for Helper {
        fn decrypt(&mut self, _: &[PKESK], skesks: &[SKESK],
                   _sym_algo: Option<SymmetricAlgorithm>,
                   decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
                   -> Result<Option<Cert>>
        {
            skesks[0].decrypt(&Password::from(NEEDLE))
                .map(|(algo, session_key)| decrypt(algo, &session_key))?;
            Ok(None)
        }
    }

    let h = Helper {};
    let mut v = DecryptorBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, h)?;

    let mut content = Vec::new();
    v.read_to_end(&mut content)?;
    assert_eq!(content, b"Hello world.");
    Ok(())
}

type Test = fn() -> ();

fn main() {
    let tests: HashMap<&'static str, Test> = [
        ("clean_basecase", clean_basecase as Test),
        ("leak_basecase", leak_basecase as Test),
        ("test_memzero", test_memzero as Test),
        ("test_libc_memset", test_libc_memset as Test),
        ("test_protected", test_protected as Test),
        ("test_protected_mpi", test_protected_mpi as Test),
        ("test_session_key", test_session_key as Test),
        ("test_encrypted", test_encrypted as Test),
        ("test_password", test_password as Test),
        ("test_ed25519", test_ed25519 as Test),
        ("test_aes_256_encryption", test_aes_256_encryption as Test),
        ("test_aes_256_decryption", test_aes_256_decryption as Test),
    ].into_iter().collect();

    let test = if let Some(t) = std::env::args().nth(1) {
        t
    } else {
        eprintln!("Usage: {} <TEST>\n\nAvailable tests:\n",
                  std::env::args().nth(0).unwrap());
        for t in tests.keys() {
            println!("{}", t);
        }
        return;
    };

    eprintln!("{}: running test", test);
    for _ in 0..N {
        if let Some(test_fn) = tests.get(test.as_str()) {
            (test_fn)();
        } else {
            panic!("unknown test case {:?}", test);
        }
    }

    scan(&test).unwrap();
}

fn scan(name: &str) -> Result<()> {
    let mut found_secret = false;

    let leaks = {
        let mut leaks = LEAKS.lock().unwrap();
        std::mem::replace(&mut *leaks, Vec::new())
    };
    let leak_count = leaks.len();
    eprintln!("{} deallocations contained leaked secrets:",
              leak_count);
    for (i, leak) in leaks.into_iter().enumerate() {
        found_secret = true;
        eprintln!("Deallocation record #{}/{}. Secret leak in allocation \
                   at {:x} (size: {} bytes), offset: {}",
                  i + 1, leak_count, leak.addr, leak.size, leak.offset);
        eprintln!("Backtrace of deallocation:\n{}", leak.backtrace);
    }

    eprintln!("Scanning all memory for leaked secrets \
               (not only deallocated memory).");

    let mut sink = std::io::stderr();
    for map in Map::iter()? {
        let map = map?;
        if map.read && map.write {
            let mut header_printed = false;
            let view = map.as_bytes()?;
            const CS: usize = 16;
            for (i, c) in view.chunks(CS).enumerate() {
                if c.iter().filter(|&b| *b == N0).count() > 7 {
                    found_secret = true;

                    if ! header_printed {
                        eprintln!("{}: {} bytes", map.pathname, map.len);
                        header_printed = true;
                    }

                    let mut d = hex::Dumper::with_offset(
                        &mut sink, "", map.start as usize + i * CS);
                    d.write_labeled(c, |_, buf| {
                        let mut s = String::with_capacity(16);
                        for b in buf {
                            assert!(N0 != b'!');
                            s.push(if *b == N0 {
                                '!'
                            } else {
                                '.'
                            });
                        }
                        Some(s)
                    })?;
                }
            }
        }
    }

    if found_secret {
        eprintln!("{}: secret leaked", name);
        std::process::exit(1);
    } else {
        eprintln!("{}: passed", name);
        Ok(())
    }
}

use std::{
    fs::File,
    io::{BufReader, BufRead},
};

#[derive(Debug)]
#[allow(dead_code)]
struct Map {
    start: u64,
    len: u64,
    read: bool,
    write: bool,
    execute: bool,
    offset: u64,
    device: String,
    inode: u64,
    pathname: String,
}

impl Map {
    fn iter() -> Result<impl Iterator<Item = Result<Map>>> {
        let f = File::open("/proc/self/maps")?;
        let f = BufReader::new(f);
        Ok(f.lines().filter_map(|l| l.ok()).map(Self::parse_line))
    }

    fn parse_line(l: String) -> Result<Self> {
        let f = l.splitn(6, ' ').collect::<Vec<_>>();
        let a = f[0].splitn(2, '-').collect::<Vec<_>>();
        let parse_hex = |s| -> Result<u64> {
            let b = hex::decode(s)?;
            let mut a = [0; 8]; // XXX word size <= u64
            let l = a.len().min(b.len());
            a[8 - l..].copy_from_slice(&b[..l]);
            Ok(u64::from_be_bytes(a))
        };
        let start = parse_hex(&a[0])?;
        let end = parse_hex(&a[1])?;
        assert!(start <= end);

        Ok(Map {
            start,
            len: end - start,
            read: f[1].as_bytes()[0] == b'r',
            write: f[1].as_bytes()[1] == b'w',
            execute: f[1].as_bytes()[2] == b'x',
            offset: parse_hex(&f[2])?,
            device: f[3].into(),
            inode: f[4].parse()?,
            pathname: f[5].trim_start().into(),
        })
    }

    fn as_bytes(&self) -> Result<&[u8]> {
        if self.read {
            let s = unsafe {
                std::slice::from_raw_parts(self.start as usize as *const _,
                                           self.len as usize)
            };
            Ok(s)
        } else {
            Err(anyhow::anyhow!("No read permissions"))
        }
    }
}
