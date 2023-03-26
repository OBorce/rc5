// Copyright (c) 2023 Boris Onchev (boris.oncev@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE or copy at http://www.boost.org/LICENSE_1_0.txt)

#![feature(iter_array_chunks)]
#![feature(array_chunks)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
use rc5::{new_rc5_dyn, RC5Algo, RC5};

macro_rules! test_concrete_vs_dynamic {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            let key = [
                0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
                0xFF, 0x48,
            ];
            let repetitions = 12;
            let rc5_concrete = RC5::<$t>::new(&key, repetitions);
            const W: usize = 8 * std::mem::size_of::<$t>();
            let rc5_dyn = new_rc5_dyn(W, repetitions, &key);

            let mut pt = [0; W * 2 / 8];
            let mut pt_dyn = pt.clone();

            assert!(rc5_concrete.is_ok());
            assert!(rc5_dyn.is_ok());

            let res = rc5_concrete.map(|rc| RC5Algo::encrypt(&rc, &mut pt));
            let res_dyn = rc5_dyn.map(|rc| RC5Algo::encrypt(&*rc, &mut pt_dyn));

            assert!(res.is_ok());
            assert!(res_dyn.is_ok());
            assert_eq!(pt[..], pt_dyn[..]);
        }
    };
}

test_concrete_vs_dynamic!(test_concrete_vs_dynamic_16, u16);
test_concrete_vs_dynamic!(test_concrete_vs_dynamic_32, u32);
test_concrete_vs_dynamic!(test_concrete_vs_dynamic_64, u64);

#[track_caller]
#[must_use]
pub fn split_in_half_mut_ref<T, const N: usize>(
    arr: &mut [T; N],
) -> (&mut [T; N / 2], &mut [T; N - N / 2])
where
    [T; N / 2]:,
    [T; N - N / 2]:,
{
    let (first_half, second_half) = arr.split_at_mut(N / 2);
    // SAFETY: first_half points to [T; N / 2]? Yes it's [T] of length N / 2 (checked by split_at)
    // second_half points to [T; N - N / 2] as that is the reminder of the array
    unsafe {
        (
            &mut *(first_half.as_mut_ptr() as *mut [T; N / 2]),
            &mut *(second_half.as_mut_ptr() as *mut [T; N - N / 2]),
        )
    }
}

macro_rules! test_encrypt_decrypt_full_message {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            let key = b"my secret key";
            let repetitions = 12;
            let rc5 = RC5::<$t>::new(key, repetitions).unwrap();

            let mut plaintext = b"hello there !!!".to_vec();
            const BLOCK_SIZE: usize = 2 * std::mem::size_of::<$t>();
            plaintext.resize(std::cmp::max(plaintext.len() % 8, BLOCK_SIZE), 0);

            let original = plaintext.clone();

            plaintext
                .array_chunks_mut::<BLOCK_SIZE>()
                .map(split_in_half_mut_ref)
                .for_each(|(mut a, mut b)| {
                    rc5.encrypt_block(&mut a, &mut b);
                });

            assert_ne!(original, plaintext);

            plaintext
                .array_chunks_mut::<BLOCK_SIZE>()
                .map(split_in_half_mut_ref)
                .for_each(|(mut a, mut b)| {
                    rc5.decrypt_block(&mut a, &mut b);
                });

            assert_eq!(original, plaintext);
        }
    };
}

test_encrypt_decrypt_full_message!(test_encrypt_decrypt_full_message_16, u16);
test_encrypt_decrypt_full_message!(test_encrypt_decrypt_full_message_32, u32);
test_encrypt_decrypt_full_message!(test_encrypt_decrypt_full_message_64, u64);
