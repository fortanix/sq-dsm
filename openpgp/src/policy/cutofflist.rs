use std::fmt;
use std::mem;
use std::ops::{Index, IndexMut};

use crate::{
    Error,
    Result,
    types::Timestamp,
    types::Duration,
};

// A `const fn` function can only use a subset of Rust's
// functionality.  The subset is growing, but we restrict ourselves to
// only use `const fn` functionality that is available in Debian
// stable, which, as of 2020, includes rustc version 1.34.2.  This
// requires a bit of creativity.
#[derive(Debug, Clone)]
pub(super) enum VecOrSlice<'a, T> {
    Vec(Vec<T>),
    Slice(&'a [T]),
    Empty(),
}

// Make a `VecOrSlice` act like a `Vec`.
impl<'a, T> VecOrSlice<'a, T> {
    // Returns an empty `VecOrSlice`.
    const fn empty() -> Self {
        VecOrSlice::Empty()
    }

    // Like `Vec::get`.
    fn get(&self, i: usize) -> Option<&T> {
        match self {
            VecOrSlice::Vec(v) => v.get(i),
            VecOrSlice::Slice(s) => s.get(i),
            VecOrSlice::Empty() => None,
        }
    }

    // Like `Vec::len`.
    fn len(&self) -> usize {
        match self {
            VecOrSlice::Vec(v) => v.len(),
            VecOrSlice::Slice(s) => s.len(),
            VecOrSlice::Empty() => 0,
        }
    }

    // Like `Vec::resize`.
    fn resize(&mut self, size: usize, value: T)
        where T: Clone
    {
        let mut v : Vec<T> = match self {
            VecOrSlice::Vec(ref mut v) => mem::replace(v, Vec::new()),
            VecOrSlice::Slice(s) => s.to_vec(),
            VecOrSlice::Empty() => Vec::with_capacity(size),
        };

        v.resize(size, value);

        *self = VecOrSlice::Vec(v);
    }
}

impl<'a, T> Index<usize> for VecOrSlice<'a, T> {
    type Output = T;

    fn index(&self, i: usize) -> &T {
        match self {
            VecOrSlice::Vec(v) => &v[i],
            VecOrSlice::Slice(s) => &s[i],
            VecOrSlice::Empty() => &[][i],
        }
    }
}

impl<'a, T> IndexMut<usize> for VecOrSlice<'a, T>
    where T: Clone
{
    fn index_mut(&mut self, i: usize) -> &mut T {
        if let VecOrSlice::Slice(s) = self {
            *self = VecOrSlice::Vec(s.to_vec());
        };

        match self {
            VecOrSlice::Vec(v) => &mut v[i],
            VecOrSlice::Slice(_) => unreachable!(),
            VecOrSlice::Empty() =>
                panic!("index out of bounds: the len is 0 but the index is {}",
                       i),
        }
    }
}

/// A given algorithm may be considered: completely broken, safe, or
/// too weak to be used after a certain time.
#[derive(Debug, Clone)]
pub(super) struct CutoffList<A> {
    // Indexed by `A as u8`.
    //
    // A value of `None` means that no vulnerabilities are known.
    //
    // Note: we use `u64` and not `SystemTime`, because there is no
    // way to construct a `SystemTime` in a `const fn`.
    pub(super) cutoffs: VecOrSlice<'static, Option<Timestamp>>,

    pub(super) _a: std::marker::PhantomData<A>,
}

pub(super) const REJECT : Option<Timestamp> = Some(Timestamp::UNIX_EPOCH);
pub(super) const ACCEPT : Option<Timestamp> = None;

pub(super) const DEFAULT_POLICY : Option<Timestamp> = REJECT;

impl<A> Default for CutoffList<A> {
    fn default() -> Self {
        Self::reject_all()
    }
}

impl<A> CutoffList<A> {
    // Rejects all algorithms.
    const fn reject_all() -> Self {
        Self {
            cutoffs: VecOrSlice::empty(),
            _a: std::marker::PhantomData,
        }
    }
}

impl<A> CutoffList<A>
    where u8: From<A>,
          A: fmt::Display,
          A: std::clone::Clone
{
    // Sets a cutoff time.
    pub(super) fn set(&mut self, a: A, cutoff: Option<Timestamp>) {
        let i : u8 = a.into();
        let i : usize = i.into();

        if i >= self.cutoffs.len() {
            // We reject by default.
            self.cutoffs.resize(i + 1, DEFAULT_POLICY)
        }
        self.cutoffs[i] = cutoff;
    }

    // Returns the cutoff time for algorithm `a`.
    #[inline]
    pub(super) fn cutoff(&self, a: A) -> Option<Timestamp> {
        let i : u8 = a.into();
        *self.cutoffs.get(i as usize).unwrap_or(&DEFAULT_POLICY)
    }

    // Checks whether the `a` is safe to use at time `time`.
    //
    // `tolerance` is added to the cutoff time.
    #[inline]
    pub(super) fn check(&self, a: A, time: Timestamp,
                        tolerance: Option<Duration>)
        -> Result<()>
    {
        if let Some(cutoff) = self.cutoff(a.clone()) {
            let cutoff = cutoff
                .checked_add(tolerance.unwrap_or_else(|| Duration::seconds(0)))
                .unwrap_or(Timestamp::MAX);
            if time >= cutoff {
                Err(Error::PolicyViolation(
                    a.to_string(), Some(cutoff.into())).into())
            } else {
                Ok(())
            }
        } else {
            // None => always secure.
            Ok(())
        }
    }
}

macro_rules! a_cutoff_list {
    ($name:ident, $algo:ty, $values_count:expr, $values:expr) => {
        // It would be nicer to just have a `CutoffList` and store the
        // default as a `VecOrSlice::Slice`.  Unfortunately, we can't
        // create a slice in a `const fn`, so that doesn't work.
        //
        // To work around that issue, we store the array in the
        // wrapper type, and remember if we are using it or a custom
        // version.
        #[derive(Debug, Clone)]
        enum $name {
            Default(),
            Custom(CutoffList<$algo>),
        }

        impl $name {
            const DEFAULTS : [ Option<Timestamp>; $values_count ] = $values;

            // Turn the `Foo::Default` into a `Foo::Custom`, if
            // necessary.
            fn force(&mut self) -> &mut CutoffList<$algo> {
                use crate::policy::cutofflist::VecOrSlice;

                if let $name::Default() = self {
                    *self = $name::Custom(CutoffList {
                        cutoffs: VecOrSlice::Vec(Self::DEFAULTS.to_vec()),
                        _a: std::marker::PhantomData,
                    });
                }

                match self {
                    $name::Custom(ref mut l) => l,
                    _ => unreachable!(),
                }
            }

            fn set(&mut self, a: $algo, cutoff: Option<Timestamp>) {
                self.force().set(a, cutoff)
            }

            fn cutoff(&self, a: $algo) -> Option<Timestamp> {
                use crate::policy::cutofflist::DEFAULT_POLICY;

                match self {
                    $name::Default() => {
                        let i : u8 = a.into();
                        let i : usize = i.into();

                        if i >= Self::DEFAULTS.len() {
                            DEFAULT_POLICY
                        } else {
                            Self::DEFAULTS[i]
                        }
                    }
                    $name::Custom(ref l) => l.cutoff(a),
                }
            }

            fn check(&self, a: $algo, time: Timestamp, d: Option<types::Duration>)
                -> Result<()>
            {
                use crate::policy::cutofflist::VecOrSlice;

                match self {
                    $name::Default() => {
                        // Convert the default to a `CutoffList` on
                        // the fly to avoid duplicating
                        // `CutoffList::check`.
                        CutoffList {
                            cutoffs: VecOrSlice::Slice(&Self::DEFAULTS[..]),
                            _a: std::marker::PhantomData,
                        }.check(a, time, d)
                    }

                    $name::Custom(ref l) => l.check(a, time, d),
                }
            }
        }
    }
}
