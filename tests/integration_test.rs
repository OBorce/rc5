// Copyright (c) 2023 Boris Onchev (boris.oncev@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE or copy at http://www.boost.org/LICENSE_1_0.txt)

#![feature(iter_array_chunks)]
#![feature(array_chunks)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
use rc5::*;

pub const BITS_IN_BYTE: usize = 8;

macro_rules! test_concrete_vs_dynamic {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            let key = [
                0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
                0xFF, 0x48,
            ];
            let repetitions = 12;
            let rc5_concrete = RC5::<$t>::new(repetitions, &key);
            const W: usize = BITS_IN_BYTE * std::mem::size_of::<$t>();
            let rc5_dyn = rc5_dyn::new(W, repetitions, &key);

            let mut pt = [0; W * 2 / BITS_IN_BYTE];
            let mut pt_dyn = pt.clone();

            assert!(rc5_concrete.is_ok());
            assert!(rc5_dyn.is_ok());

            let res = rc5_concrete.map(|rc| rc5_dyn::RC5Algo::encrypt(&rc, &mut pt));
            let res_dyn = rc5_dyn.map(|rc| rc5_dyn::RC5Algo::encrypt(&*rc, &mut pt_dyn));

            assert!(res.is_ok());
            assert!(res_dyn.is_ok());
            assert_eq!(pt[..], pt_dyn[..]);
        }
    };
}

test_concrete_vs_dynamic!(test_concrete_vs_dynamic_16, u16);
test_concrete_vs_dynamic!(test_concrete_vs_dynamic_32, u32);
test_concrete_vs_dynamic!(test_concrete_vs_dynamic_64, u64);

macro_rules! test_encrypt_decrypt_full_message {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            let key = b"my secret key";
            let repetitions = 12;
            let rc5 = RC5::<$t>::new(repetitions, key).unwrap();

            let mut plaintext = b"hello there !!!".to_vec();
            const BLOCK_SIZE: usize = 2 * std::mem::size_of::<$t>();
            let padding_size = (BLOCK_SIZE - key.len() % BLOCK_SIZE) % BLOCK_SIZE;
            plaintext.resize(plaintext.len() + padding_size, 0);

            let original = plaintext.clone();

            plaintext.array_chunks_mut().for_each(|mut block_chunk| {
                rc5.encrypt_block(&mut block_chunk);
            });

            assert_ne!(original, plaintext);

            plaintext.array_chunks_mut().for_each(|mut block_chunk| {
                rc5.decrypt_block(&mut block_chunk);
            });

            assert_eq!(original, plaintext);
        }
    };
}

test_encrypt_decrypt_full_message!(test_encrypt_decrypt_full_message_16, u16);
test_encrypt_decrypt_full_message!(test_encrypt_decrypt_full_message_32, u32);
test_encrypt_decrypt_full_message!(test_encrypt_decrypt_full_message_64, u64);
