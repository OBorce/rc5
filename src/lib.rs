// Copyright (c) 2023 Boris Onchev (boris.oncev@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE or copy at http://www.boost.org/LICENSE_1_0.txt)

//! This library provides an implementation of the RC5 block cipher algorithm
//!
//! The RC5 block cipher is a symmetric-key block cipher designed by Ron Rivest in 1994.
//! It has a variable block size (32, 64, or 128 bits), a variable key size (0 to 2040 bits),
//! and a variable number of rounds (0 to 255).
//!
//! The RC5 algorithm operates on two words (16-bit, 32-bit, or 64-bit each) at a time, with
//! each word being represented by a generic type `T`. The algorithm is based on a key
//! expansion process that generates a series of round keys, which are used to encrypt
//! and decrypt the data.
//!
#![feature(iter_array_chunks)]
#![feature(split_array)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod algorithm;
mod chunker;
mod type_traits;

pub use crate::algorithm::*;
