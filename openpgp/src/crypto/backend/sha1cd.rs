use crate::crypto::hash::Digest;
use crate::Result;

pub(crate) fn build() -> sha1collisiondetection::Sha1CD {
    sha1collisiondetection::Builder::default()
        .detect_collisions(true)
        .use_ubc(true)
        .safe_hash(true)
        .build()
}

impl Digest for sha1collisiondetection::Sha1CD {
    fn digest_size(&self) -> usize {
        20
    }

    fn update(&mut self, data: &[u8]) {
        digest::Update::update(self, data);
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        let mut d =
            generic_array::GenericArray::<u8, digest::consts::U20>::default();
        let r = self.finalize_into_dirty_cd(&mut d);
        digest::Reset::reset(self);
        let l = digest.len().min(d.len());
        &mut digest[..l].copy_from_slice(&d[..l]);
        r.map_err(Into::into)
    }
}
