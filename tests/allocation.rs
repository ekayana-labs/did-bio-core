//! Decoding never allocates far beyond its input. The test binary counts the
//! largest single allocation, so it lives in a file of its own.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use did_bio_core::account::{DidAccountState, ACCOUNT_DISCRIMINATOR};

struct Largest;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Largest = Largest;

/// An image whose service count covers every remaining byte, so a decoder
/// that trusted the count would reserve dozens of times the input.
fn hostile(size: usize) -> Vec<u8> {
    let mut image = ACCOUNT_DISCRIMINATOR.to_vec();
    image.extend_from_slice(&1u64.to_le_bytes());
    image.push(255);
    image.extend_from_slice(&[1u8; 32]);
    image.push(0);
    image.extend_from_slice(&0i64.to_le_bytes());
    image.extend_from_slice(&[0u8; 12]);
    let count = (size - image.len() - 4) as u32;
    image.extend_from_slice(&count.to_le_bytes());
    image.resize(size, 0);
    image
}

#[test]
fn hostile_counts_allocate_nothing_large() {
    for size in [64 * 1024, 1024 * 1024, 10 * 1024 * 1024] {
        let image = hostile(size);
        LARGEST.store(0, Ordering::Relaxed);
        assert!(DidAccountState::from_account_data(&image).is_err());
        let largest = LARGEST.load(Ordering::Relaxed);
        assert!(
            largest <= 4096,
            "a {size} byte image made a {largest} byte allocation"
        );
    }
}
