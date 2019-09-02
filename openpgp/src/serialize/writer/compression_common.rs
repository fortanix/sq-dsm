//! Common code for the compression writers.

use crate::{
    Error,
    Result,
};

/// Compression level.
///
/// This value is used by the encoders to tune their compression
/// strategy.  The level is restricted to levels commonly used by
/// compression libraries, `0` to `9`, where `0` means no compression,
/// `1` means fastest compression, `6` being a good default, and
/// meaning `9` best compression.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressionLevel(u8);

impl Default for CompressionLevel {
    fn default() -> Self {
        Self(6)
    }
}

impl CompressionLevel {
    /// Creates a new compression level.
    ///
    /// `level` must be in range `0..10`, where `0` means no
    /// compression, `1` means fastest compression, `6` being a good
    /// default, and meaning `9` best compression.
    pub fn new(level: u8) -> Result<CompressionLevel> {
        if level < 10 {
            Ok(Self(level))
        } else {
            Err(Error::InvalidArgument(
                format!("compression level out of range: {}", level)).into())
        }
    }

    /// No compression.
    pub fn none() -> CompressionLevel {
        Self(0)
    }

    /// Fastest compression.
    pub fn fastest() -> CompressionLevel {
        Self(1)
    }
    /// Best compression.
    pub fn best() -> CompressionLevel {
        Self(9)
    }
}

#[cfg(feature = "compression-deflate")]
mod into_deflate_compression {
    use flate2::Compression;
    use super::*;

    impl From<CompressionLevel> for Compression {
        fn from(l: CompressionLevel) -> Self {
            Compression::new(l.0 as u32)
        }
    }
}

#[cfg(feature = "compression-bzip2")]
mod into_bzip2_compression {
    use bzip2::Compression;
    use super::*;

    impl From<CompressionLevel> for Compression {
        fn from(l: CompressionLevel) -> Self {
            if l <= CompressionLevel::fastest() {
                Compression::Fastest
            } else if l <= CompressionLevel::default() {
                Compression::Default
            } else {
                Compression::Best
            }
        }
    }
}
