//! A signature verification cache.
//!
//! Signature verification is expensive.  To mitigate this, Sequoia
//! includes a signature verification cache.  This is keyed on the
//! hash of the signature's context: the signature MPIs, the computed
//! hash, and the key.  Since this context is needed to use the cache,
//! it's hard to misuse the cache.
//!
//! The signature cache also supports dumping and restoring the cache
//! from disk (see [`SignatureVerificationCache::restore`] and
//! [`SignatureVerificationCache::dump`]).  This is particularly
//! useful for one-shot programs, which don't have enough time to warm
//! the cache up.
//!
//! The cache file needs to be managed carefully.  In particular, you
//! probably don't want to allow it to grow without bound.  To help
//! manage the cache, the cache keeps track of whether an entry was
//! added ([`Entry::inserted`]), and whether it was accessed
//! ([`Entry::accessed`]).
use std::cmp;
use std::collections::BTreeMap;
use std::collections::btree_map;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use crate::HashAlgorithm;
use crate::Result;
use crate::packet::Key;
use crate::packet::Signature;
use crate::packet::key;

const TRACE: bool = false;

/// The cache singleton.
static SIGNATURE_VERIFICATION_CACHE: SignatureVerificationCache
    = SignatureVerificationCache::empty();

/// The hash algorithm that we use.
///
/// SHA-512 is faster than SHA-256 on 64-bit hardware.
const HASH_ALGO: HashAlgorithm = HashAlgorithm::SHA512;

/// We use SHA-512, which has 512 / 8 bytes = 64 bytes.  We truncate
/// it to the first 256 bits, i.e. we do SHA-512-256.  We're only
/// worried about second pre-image resistance, so this is enough even
/// when the signature uses SHA-512.
const HASH_BYTES_UNTRUNCATED: usize = 512 / 8;
const HASH_BYTES_TRUNCATED: usize = HASH_BYTES_UNTRUNCATED / 2;

// The value of a cache entry.
const VALUE_BYTES: usize = HASH_BYTES_TRUNCATED;
type Value = [u8; VALUE_BYTES];
const VALUE_NULL: Value = [0u8; VALUE_BYTES];

/// Information about a cache entry.
#[derive(Debug)]
pub struct Metadata {
    /// Whether the entry was inserted.
    ///
    /// Entries added by [`SignatureVerificationCache::restore`] have
    /// this cleared.  Entries added as a side effect of a signature
    /// verification have this set.
    inserted: bool,

    /// Whether the entry is accessed.
    ///
    /// An entry added by [`SignatureVerificationCache::restore`]
    /// initially is not considered to have been accessed.  This is
    /// set when an entry is used by the signature verification code.
    accessed: AtomicBool,
}

impl Clone for Metadata {
    fn clone(&self) -> Metadata {
        Self {
            inserted: self.inserted,
            accessed: AtomicBool::from(self.accessed.load(Ordering::Relaxed)),
        }
    }
}

impl Metadata {
    /// Instantiate a value.
    ///
    /// Entries added by [`SignatureVerificationCache::restore`] have
    /// this cleared.  Entries added as a side effect of a signature
    /// verification have this set.
    fn new(inserted: bool) -> Self {
        Metadata {
            inserted,
            accessed: false.into(),
        }
    }

    /// Whether the entry was inserted since the program started.
    ///
    /// Entries added by [`SignatureVerificationCache::restore`] have
    /// this cleared.  Entries added as a side effect of a signature
    /// verification have this set.
    pub fn inserted(&self) -> bool {
        self.inserted
    }

    /// Whether the entry was accessed.
    ///
    /// An entry added by [`SignatureVerificationCache::restore`]
    /// initially is not considered to have been accessed.  This is
    /// set when an entry is used by the signature verification code.
    pub fn accessed(&self) -> bool {
        self.accessed.load(Ordering::Relaxed)
    }
}

/// An entry in the signature verification cache.
///
/// You can iterate over the cache using
/// [`SignatureVerificationCache::dump`].
///
/// Two entries are considered equal if their values are identical;
/// the metadata is ignored.
#[derive(Clone)]
pub struct Entry {
    value: Value,
    metadata: Metadata,
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == cmp::Ordering::Equal
    }
}

impl Eq for Entry {}

impl Entry {
    /// Computes the cache entry from the signature and its context.
    pub(super) fn new(sig: &Signature,
                      computed_digest: &[u8],
                      key: &Key<key::PublicParts, key::UnspecifiedRole>)
        -> Result<Self>
    {
        use crate::serialize::Marshal;
        use crate::serialize::MarshalInto;

        // Hash(Version || Signature MPIs Len || Signature MPIs || Hash Algorithm || Digest || Key MPIs)
        //
        // - Version: one byte, currently 0.
        // - Signature MPIs: 4 bytes, little endian
        // - Signature MPIs: variable number of bytes, the signature's MPIs
        // - Hash algorithm: one byte, the hash algorithm
        // - Digest: HashAlgorithm::len() bytes, the digest's length
        // - Key: variable number of bytes, the key's MPIs
        let mut context = HASH_ALGO.context()?.for_digest();

        // Version.
        context.update(&[ 0u8 ]);

        // MPIs.
        let mpis_len = sig.mpis.serialized_len();
        context.update(&[
            (mpis_len & 0xFF) as u8,
            ((mpis_len >> 8) & 0xFF) as u8,
            ((mpis_len >> 16) & 0xFF) as u8,
            ((mpis_len >> 24) & 0xFF) as u8,
        ]);
        sig.mpis.export(&mut context)?;

        // Hash algorithm.
        context.update(&[
            u8::from(sig.hash_algo())
        ]);

        // Hash.
        context.update(computed_digest);

        // Keys.
        key.mpis().export(&mut context)?;

        let context_hash = context.into_digest()?;

        let mut value = VALUE_NULL;
        value.copy_from_slice(&context_hash[..VALUE_BYTES]);

        Ok(Entry {
            value,
            metadata: Metadata::new(true),
        })
    }

    /// Returns the cache entry's value.
    ///
    /// This value is opaque and must not be interpreted.
    ///
    /// You can write this value to disk, and restore it using
    /// [`SignatureVerificationCache::restore`].
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns whether the entry is in the cache.
    pub(super) fn present(&self) -> bool {
        SIGNATURE_VERIFICATION_CACHE.present(&self.value)
    }

    /// Inserts the entry in the cache.
    ///
    /// `verified` indicates whether the signature could be verified
    /// (`true`), or not (`false`).
    pub(super) fn insert(self, verified: bool) {
        // We don't cache negative results.
        if verified {
            SIGNATURE_VERIFICATION_CACHE.insert(self.value);
        }
    }

    /// Whether the entry was inserted since the program started.
    ///
    /// Entries added by [`SignatureVerificationCache::restore`] have
    /// this cleared.  Entries added as a side effect of a signature
    /// verification have this set.
    pub fn inserted(&self) -> bool {
        self.metadata.inserted
    }

    /// Whether the entry was accessed.
    ///
    /// An entry added by [`SignatureVerificationCache::restore`]
    /// initially is not considered to have been accessed.  This is
    /// set when an entry is used by the signature verification code.
    pub fn accessed(&self) -> bool {
        self.metadata.accessed.load(Ordering::Relaxed)
    }
}

/// We split on the `BUCKETS_BITS` most significant bits of the value
/// to reduce locking contention.
const BUCKETS_BITS: usize = 4;
const BUCKETS: usize = 1 << BUCKETS_BITS;
const BUCKETS_SHIFT: usize = 8 - BUCKETS_BITS;

/// A signature verification cache.
pub struct SignatureVerificationCache {
    /// A sorted list of entries.  This is filled by
    /// `SignatureVerificationCache::restore`, and is much faster than
    /// filling the btrees.
    list: OnceLock<Vec<Entry>>,

    /// The buckets.
    buckets: [
        RwLock<BTreeMap<Value, Metadata>>;
        BUCKETS
    ],

    /// The number of cache hits.
    hits: AtomicUsize,
    /// The number of cache misses.
    misses: AtomicUsize,
    /// The number of entries that were restored (i.e., not inserted).
    preloads: AtomicUsize,
    /// The number of entries that were inserted (i.e., not restored).
    insertions: AtomicUsize,
}

impl SignatureVerificationCache {
    const fn empty() -> Self {
        SignatureVerificationCache {
            list: OnceLock::new(),
            buckets: [
                // 0
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                // 8
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
            ],
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
            preloads: AtomicUsize::new(0),
            insertions: AtomicUsize::new(0),
        }
    }

    /// Returns the bucket that a cache entry goes into.
    fn bucket(value: &[u8]) -> usize {
        (value[0] >> BUCKETS_SHIFT) as usize
    }

    /// Returns whether the cache contains `value`.
    fn present(&self, value: &[u8]) -> bool {
        assert_eq!(value.len(), HASH_BYTES_TRUNCATED);

        // First search in our restored list.  It's sorted so we can
        // use binary search.
        if let Some(list) = self.list.get() {
            if let Ok(i) = list.binary_search_by(|e| e.value[..].cmp(value)) {
                list[i].metadata.accessed.store(true, Ordering::Relaxed);
                self.hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        // Fallback to searching the buckets.
        let i = Self::bucket(value);
        let entries = self.buckets[i].read().unwrap();
        if let Some(metadata) = entries.get(value) {
            metadata.accessed.store(true, Ordering::Relaxed);
            self.hits.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Inserts a verified signature into the cache.
    fn insert(&self, value: [u8; HASH_BYTES_TRUNCATED]) {
        let i = Self::bucket(&value);
        let mut entries = self.buckets[i].write().unwrap();
        match entries.entry(value) {
            btree_map::Entry::Vacant(e) => {
                // The entry is new.  Note it.
                self.insertions.fetch_add(1, Ordering::Relaxed);

                // Add the entry.
                e.insert(Metadata::new(true));
            }
            btree_map::Entry::Occupied(_e) => {
                // Nothing to do.
            }
        }
    }

    /// Returns the number of cache hits.
    pub fn cache_hits() -> usize {
        SIGNATURE_VERIFICATION_CACHE.hits.load(Ordering::Relaxed)
    }

    /// Returns the number of cache misses.
    pub fn cache_misses() -> usize {
        SIGNATURE_VERIFICATION_CACHE.misses.load(Ordering::Relaxed)
    }

    /// Returns the number of cache insertions.
    ///
    /// This returns the number of times an entry was added to the
    /// cache since the program started or the last time
    /// [`SignatureVerificationCache::clear_insertions`] was called.
    ///
    /// This does not include entries added via
    /// [`SignatureVerificationCache::restore`].
    pub fn insertions() -> usize {
        SIGNATURE_VERIFICATION_CACHE.insertions.load(Ordering::Relaxed)
    }

    /// Resets the insertions counter.
    pub fn clear_insertions() {
        SIGNATURE_VERIFICATION_CACHE.insertions.store(0, Ordering::Relaxed);
    }

    /// Restores the signature verification cache.
    ///
    /// This merges the entries into the existing signature cache.
    ///
    /// The values are the values as returned by [`Entry::value`].
    ///
    /// The iterator is `Send`, `Sync` and `'static`, because this
    /// function may spawn a thread to avoid blocking the main thread.
    ///
    /// When the restore is complete, `finished` is called.
    pub fn restore<'a, F>(
        entries: impl Iterator<Item=Vec<u8>> + Send + Sync + 'static,
        finished: F)
        where F: FnOnce() + Send + Sync + 'static
    {
        tracer!(TRACE, "SignatureVerificationCache::restore");

        // Sanity check the constants here: this function is run O(1)
        // times.

        assert_eq!(HASH_ALGO.context().expect("have SHA-512")
                   .for_digest().digest_size(),
                   HASH_BYTES_UNTRUNCATED);
        assert!(HASH_BYTES_TRUNCATED <= HASH_BYTES_UNTRUNCATED);

        // Must fit in a byte.
        assert!(BUCKETS_BITS <= 8);

        // Consistency check.
        assert_eq!(BUCKETS, 1 << BUCKETS_BITS);

        std::thread::spawn(move || {
            let mut items: Vec<Entry> = Vec::with_capacity(32 * 1024);

            let mut bad = 0;
            let mut count = 0;

            for entry in entries {
                count += 1;
                if entry.len() != VALUE_BYTES {
                    bad += 1;
                    continue;
                }

                let mut value = VALUE_NULL;
                value.copy_from_slice(&entry[..VALUE_BYTES]);

                items.push(Entry {
                    value,
                    metadata: Metadata::new(false),
                });
            }

            if bad > 0 {
                t!("Warning: {} of {} cache entries could not be read",
                   bad, count);
            }
            t!("Restored {} entries", count);

            SIGNATURE_VERIFICATION_CACHE.preloads
                .fetch_add(items.len(), Ordering::Relaxed);

            items.sort();

            // If this is the first restore, then we can store the
            // signatures in the list.
            if let Err(items) = SIGNATURE_VERIFICATION_CACHE.list.set(items) {
                // Hmm, another restore.  This is unusual, but okay.
                // We add the signatures to the buckets, as we can't
                // change the list: it is behind a OnceLock.
                let mut bucket_i = 0;
                let mut bucket = SIGNATURE_VERIFICATION_CACHE
                    .buckets[bucket_i].write().unwrap();
                for item in items.into_iter() {
                    let i = Self::bucket(&item.value);
                    if i != bucket_i {
                        // Items should be sorted so we should move
                        // from one bucket to the next.
                        assert!(i > bucket_i);
                        bucket = SIGNATURE_VERIFICATION_CACHE
                            .buckets[i].write().unwrap();
                        bucket_i = i;
                    }

                    bucket.insert(item.value, item.metadata);
                }
            }

            finished();
          });
    }

    /// Dumps the contents of the cache.
    ///
    /// This clones the cache to avoid holding locks too long.
    ///
    /// The values returned by [`Entry::value`] may be written to a
    /// file, and restored using
    /// [`SignatureVerificationCache::restore`].
    ///
    /// Before saving them, you may want to check if there were any
    /// insertions using [`SignatureVerificationCache::insertions`].
    ///
    /// Also, you may want to prune the entries to avoid having the
    /// cache grow without bound.
    pub fn dump<'a>() -> impl IntoIterator<Item=Entry> {
        tracer!(TRACE, "SignatureVerificationCache::dump");

        if TRACE {
            let preloads = SIGNATURE_VERIFICATION_CACHE
                .preloads.load(Ordering::Relaxed);
            let insertions = SIGNATURE_VERIFICATION_CACHE
                .insertions.load(Ordering::Relaxed);

            t!("{} entries: {} restored, {} inserted",
               preloads + insertions,
               preloads, insertions);

            let hits = SIGNATURE_VERIFICATION_CACHE
                .hits.load(Ordering::Relaxed);
            let misses = SIGNATURE_VERIFICATION_CACHE
                .misses.load(Ordering::Relaxed);
            let lookups = hits + misses;
            if lookups > 0 {
                t!("{} cache lookups, {} hits ({}%), {} misses ({}%)",
                   lookups,
                   hits, (100 * hits) / lookups,
                   misses, (100 * misses) / lookups);
            } else {
                t!("0 cache lookups");
            }
        }

        DumpIter {
            bucket: 0,
            iter: None,
            list: SIGNATURE_VERIFICATION_CACHE.list.get()
                .map(|list| list.clone())
                .unwrap_or(Vec::new()),
        }
    }
}

/// Iterates over all entries in the cache.
///
/// Note: to reduce lock contention, this may return individual entries
/// added after it was instantiated.
struct DumpIter {
    iter: Option<std::vec::IntoIter<Entry>>,

    // The next bucket to dump.  Once we get to `BUCKETS`, we dump
    // `list`.
    bucket: usize,

    // If we verify an entry before the cache is restored, the entry
    // could end in both SignatureVerificationCache.list and a bucket.
    // Avoid dumping an entry twice.
    list: Vec<Entry>,
}

impl Iterator for DumpIter {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        tracer!(TRACE, "DumpIter::next");

        loop {
            if let Some(ref mut iter) = self.iter {
                if let Some(item) = iter.next() {
                    return Some(item);
                }
            }

            if self.bucket == BUCKETS {
                if self.list.is_empty() {
                    return None;
                }

                let list = std::mem::take(&mut self.list);
                t!("Dumping {} restored entries", list.len());
                self.iter = Some(list.into_iter());
            } else {
                let bucket = &SIGNATURE_VERIFICATION_CACHE.buckets[self.bucket];
                self.bucket += 1;

                let bucket = bucket.read().unwrap();

                t!("Dumping {} entries from bucket {}",
                   bucket.len(), self.bucket - 1);

                self.iter = Some(
                    bucket.iter()
                        .filter_map(|(v, m)| {
                            // If the entry is also in list, then we
                            // don't want to return it twice.
                            if let Ok(_) = self.list.binary_search_by(|e| {
                                e.value[..].cmp(v)
                            })
                            {
                                // This is a dupe.  Skip it.
                                None
                            } else {
                                Some(Entry {
                                    value: v.clone(),
                                    metadata: m.clone(),
                                })
                            }
                        })
                        .collect::<Vec<_>>()
                        .into_iter())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bucket() {
        // Assert that all the buckets have the same number of items.
        let mut bucket = 0;
        let mut bucket_count = vec![0; BUCKETS];

        for i in 0..=u8::MAX {
            let mut value = VALUE_NULL;
            value[0] = i;
            let b = SignatureVerificationCache::bucket(&value);

            if b != bucket {
                // Different bucket.  Since we are using the most
                // significant bits, it must be the next bucket.
                assert_eq!(b, bucket + 1);
                bucket = bucket + 1;
            }
            bucket_count[b] += 1;
        }

        for (i, c) in bucket_count.iter().enumerate() {
            eprintln!("{}: {}", i, c);
        }

        assert!(bucket_count.iter().all(|c| *c == bucket_count[0]));
        assert_eq!(bucket_count.iter().map(|c| *c as usize).sum::<usize>(),
                   u8::MAX as usize + 1);
    }
}
