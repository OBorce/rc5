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

#[track_caller]
#[must_use]
pub fn split_in_half_mut_ref<T, const N: usize>(arr: &mut [T; N * 2]) -> (&mut [T; N], &mut [T; N])
where
    [T; N * 2]:,
{
    let (first_half, second_half) = arr.split_at_mut(N);
    // SAFETY: We know the size of the array at is N * 2 so splitting at N will give us two halves
    // of N elements each
    unsafe {
        (
            &mut *(first_half.as_mut_ptr() as *mut [T; N]),
            &mut *(second_half.as_mut_ptr() as *mut [T; N]),
        )
    }
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

    #[test]
    fn split_in_half_8_to_4() {
        let mut arr = [1, 2, 3, 4, 5, 6, 7, 8];
        {
            let (left, right) = split_in_half_mut_ref::<u32, 4>(&mut arr);
            assert_eq!(*left, [1, 2, 3, 4]);
            assert_eq!(*right, [5, 6, 7, 8]);
            left[0] = 0;
            right[0] = 0;
        }
        assert_eq!(arr, [0, 2, 3, 4, 0, 6, 7, 8]);
    }
}
