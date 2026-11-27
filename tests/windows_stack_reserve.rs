//! WIN-002: `tetron.exe` reserves an 8 MiB main-thread stack. Windows'
//! 1 MiB default overflows on the clap command tree in debug builds.
#![cfg(windows)]

/// `SizeOfStackReserve` from a PE32+ image.
fn stack_reserve(image: &[u8]) -> u64 {
    let u16_at = |o: usize| u16::from_le_bytes([image[o], image[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes(image[o..o + 4].try_into().unwrap());
    assert_eq!(&image[..2], b"MZ", "not a PE image");
    let pe = u32_at(0x3C) as usize;
    assert_eq!(&image[pe..pe + 4], b"PE\0\0", "missing PE signature");
    let opt = pe + 4 + 20; // signature + COFF file header
    assert_eq!(u16_at(opt), 0x20B, "not PE32+");
    u64::from_le_bytes(image[opt + 72..opt + 80].try_into().unwrap())
}

#[test]
fn tetron_exe_reserves_8_mib_stack() {
    let image = std::fs::read(env!("CARGO_BIN_EXE_tetron")).unwrap();
    assert!(stack_reserve(&image) >= 8 * 1024 * 1024);
}
