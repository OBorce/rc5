// Copyright (c) 2023 Boris Onchev (boris.oncev@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE or copy at http://www.boost.org/LICENSE_1_0.txt)

//! Traits for working with cryptographic algorithms that require bitwise rotation and conversion to
//! and from byte arrays.
//!

/// A trait for unsigned types that calls the `rotate_left` or `rotate_right` standard functions
pub trait BitRotabable<T: num_traits::Unsigned> {
    type Output;

    fn rotate_left(self, x: T) -> Self::Output;
    fn rotate_right(self, x: T) -> Self::Output;
}

macro_rules! impl_bit_rotatable {
    ($t:ty, $t2:ty) => {
        impl BitRotabable<$t> for $t2 {
            type Output = $t2;

            fn rotate_left(self, x: $t) -> Self::Output {
                self.rotate_left(rotation_amount::<Self::Output>(x as u32))
            }

            fn rotate_right(self, x: $t) -> Self::Output {
                self.rotate_right(rotation_amount::<Self::Output>(x as u32))
            }
        }
    };
}

impl_bit_rotatable!(u16, u16);
impl_bit_rotatable!(u32, u16);
impl_bit_rotatable!(u32, u64);
impl_bit_rotatable!(u32, u32);
impl_bit_rotatable!(u64, u64);

/// A trait for types that can be created from a `u64` value.
pub trait FromU64 {
    fn from_u64(v: u64) -> Self;
}

macro_rules! impl_from_u64 {
    ($($ty:ty)*) => {
        $(
            impl FromU64 for $ty {
                #[inline]
                fn from_u64(v: u64) -> $ty {
                    v as $ty
                }
            }
        )*
    }
}

impl_from_u64!(u16 u32 u64);

/// A trait for types that can be converted to and from little-endian byte arrays.
pub trait FromToLeBytes<T: num_traits::Unsigned> {
    fn from_le_bytes(bytes: [u8; std::mem::size_of::<T>()]) -> T;
    fn to_le_bytes(self) -> [u8; std::mem::size_of::<T>()];
}

macro_rules! impl_from_to_bytes {
    ($($t:ty)*) => {
        $(
            impl FromToLeBytes<$t> for $t {
                fn from_le_bytes(bytes: [u8; std::mem::size_of::<$t>()]) -> $t {
                    <$t>::from_le_bytes(bytes)
                }

                fn to_le_bytes(self) -> [u8; std::mem::size_of::<$t>()] {
                    <$t>::to_le_bytes(self)
                }
            }
        )*
    };
}

impl_from_to_bytes!(u16 u32 u64);

fn rotation_amount<T>(x: u32) -> u32 {
    x % (std::mem::size_of::<T>() * 8) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_amount_wrap() {
        let x = 0xffffff;
        let expected = 0xf;
        let amount = rotation_amount::<u16>(x);
        assert_eq!(expected, amount);
    }

    #[test]
    fn rotation_amount_nowrap() {
        let x = 4;
        let amount = rotation_amount::<u16>(x);
        assert_eq!(x, amount);
    }
}
