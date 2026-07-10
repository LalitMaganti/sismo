// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Per-thread Poisson allocation sampler (port of heapprofd's `sampler.h`,
//! from heap_preload_macos.zig).
//!
//! A per-thread countdown drawn from Exponential(1/interval) is decremented by
//! each allocation's size; on crossing ≤ 0 the alloc is sampled with weight =
//! `sampling_interval × num_crossings`, so the recorded `sample_size` is an
//! unbiased estimate of the byte mass it stands in for. Allocations ≥ the
//! interval are always sampled at their real size. No allocation on any path —
//! this runs inside the malloc interposer.

/// xoshiro256** — a small, fast, alloc-free PRNG. Seeded via splitmix64 so a
/// single u64 seed fills the 256-bit state well. (heap_preload_macos used
/// std.Random.Xoshiro256; sampling is statistical, so the exact stream needn't
/// match — only the distribution matters.)
pub struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    pub fn new(seed: u64) -> Self {
        let mut sm = seed;
        let mut splitmix = || {
            sm = sm.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = sm;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        Xoshiro256 { s: [splitmix(), splitmix(), splitmix(), splitmix()] }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }
}

pub struct Sampler {
    sampling_interval: u64,
    rate: f64,
    interval_to_next: i64,
    rng: Xoshiro256,
}

impl Sampler {
    pub fn new(interval: u64, seed: u64) -> Self {
        let mut s = Sampler {
            sampling_interval: interval,
            rate: 1.0 / interval as f64,
            interval_to_next: 0,
            rng: Xoshiro256::new(seed),
        };
        s.interval_to_next = s.next_interval();
        s
    }

    /// Inverse-CDF sample of Exp(rate=1/interval): x = -ln(U)/rate, U~U(0,1].
    /// The +1 converts "failures before next success" to "interval including
    /// the next success" — the same adjustment heapprofd makes.
    fn next_interval(&mut self) -> i64 {
        let mut u = self.rng.next_u64() as f64 / u64::MAX as f64;
        if u <= 0.0 {
            u = 1e-300; // guard against ln(0)
        }
        let x = -u.ln() / self.rate;
        x as i64 + 1
    }

    /// Decide the weighted sample size for an allocation of `alloc_sz` bytes.
    /// Returns 0 to skip, else `sampling_interval × num_crossings` (the byte
    /// mass this sampled record represents). Allocations ≥ the interval are
    /// always sampled at real size.
    pub fn sample_size(&mut self, alloc_sz: u64) -> u64 {
        if alloc_sz >= self.sampling_interval {
            return alloc_sz;
        }
        self.interval_to_next -= alloc_sz as i64;
        let mut num_samples: u64 = 0;
        while self.interval_to_next <= 0 {
            self.interval_to_next += self.next_interval();
            num_samples += 1;
        }
        self.sampling_interval * num_samples
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_allocs_sampled_at_real_size() {
        let mut s = Sampler::new(4096, 1);
        assert_eq!(s.sample_size(4096), 4096);
        assert_eq!(s.sample_size(1 << 20), 1 << 20);
    }

    #[test]
    fn small_alloc_sample_size_is_zero_or_a_multiple_of_interval() {
        let interval = 4096;
        let mut s = Sampler::new(interval, 42);
        for _ in 0..10_000 {
            let ss = s.sample_size(64);
            assert!(ss == 0 || ss % interval == 0);
        }
    }

    #[test]
    fn total_sample_size_is_an_unbiased_estimate() {
        // Over many small allocations the summed weighted sample_size should
        // approximate the true total byte mass (that's the whole point of the
        // Poisson weighting). Tolerate 15% — it's a statistical estimator.
        let interval = 4096;
        let mut s = Sampler::new(interval, 0xC0FFEE);
        let alloc = 128u64;
        let n = 200_000u64;
        let mut total_sampled = 0u64;
        for _ in 0..n {
            total_sampled += s.sample_size(alloc);
        }
        let true_total = alloc * n; // 25.6 MB
        let ratio = total_sampled as f64 / true_total as f64;
        assert!(ratio > 0.85 && ratio < 1.15, "estimator ratio {ratio} out of range");
    }

    #[test]
    fn xoshiro_is_deterministic_and_varied() {
        let mut a = Xoshiro256::new(7);
        let mut b = Xoshiro256::new(7);
        let mut c = Xoshiro256::new(8);
        assert_eq!(a.next_u64(), b.next_u64()); // same seed → same stream
        assert_ne!(a.next_u64(), c.next_u64()); // different seed → diverges
    }
}
