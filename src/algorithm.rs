// Copyright (c) 2023 Boris Onchev (boris.oncev@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE or copy at http://www.boost.org/LICENSE_1_0.txt)

//! The implementaton details of the RC5 block cipher algorithm
//!
use crate::chunker::*;
use crate::type_traits::*;
use std::cmp::max;
use std::cmp::min;

const NUM_WORDS_PER_BLOCK: usize = 2;
const MAX_KEY_SIZE: usize = 255;

/// The RC5 struct represents an instance of the RC5 block cipher algorithm.
///
/// The `RC5` struct provides methods for initializing the algorithm with a key and
/// a number of rounds, as well as methods for encrypting and decrypting individual
/// words and blocks of data.
pub struct RC5<T> {
    //TODO: maybe add an allocator support
    s_arr: Box<[[T; NUM_WORDS_PER_BLOCK]]>,
    s0: T,
    s1: T,
}

/// Holds the S and L arrays,
/// used in the init step of RC5
struct SLArrays<T> {
    s_arr: Box<[T]>,
    l_arr: Box<[T]>,
}

impl<T> RC5<T>
where
    T: num_traits::Unsigned
        + FromToLeBytes<T>
        + FromU64
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + std::marker::Copy
        + std::ops::BitXor<T, Output = T>
        + BitRotabable<T, Output = T>
        + BitRotabable<u32, Output = T>,
    [u8; std::mem::size_of::<T>()]:,
{
    /// Creates a new RC5 instance with the given key, number of repetitions, and block size.
    ///
    /// The `key` parameter is a slice of bytes representing the secret key used to encrypt
    /// and decrypt the data. The `repetitions` parameter specifies the number of times
    /// the key expansion process should be repeated (typically 12, 16, or 20), and the `p` and `q`
    /// parameters are computed from the base of natura logorithms and golden ration numbers for
    /// the specific word size.
    ///
    /// # Examples
    ///
    /// ```
    /// use rc5::RC5;
    ///
    /// let key = b"my secret key";
    /// let rc5 = RC5::<u32>::new(12, key);
    /// ```
    pub fn new(repetitions: u8, key: &[u8]) -> Result<RC5<T>, RC5InitError> {
        if key.len() > MAX_KEY_SIZE {
            return Err(RC5InitError::InvalidKeySize(key.len()));
        }

        let sl_arrays = RC5::init_sl_arrays(repetitions, key);

        Ok(RC5::mix_sl_arrays(sl_arrays))
    }

    fn init_sl_arrays(repetitions: u8, key: &[u8]) -> SLArrays<T> {
        let p = pw::<T>();
        let q = qw::<T>();

        let t_num_bytes: usize = std::mem::size_of::<T>();
        let l_padding_size = match key.len() {
            // if empty add at least 1 T
            0 => t_num_bytes,
            // else pad any incomplete T
            len => (t_num_bytes - (len % t_num_bytes)) % t_num_bytes,
        };
        let l_iter = std::iter::repeat(0)
            .take(l_padding_size)
            .chain(key.iter().copied())
            .array_chunks()
            .map(T::from_le_bytes);

        let t = 2 * (repetitions as usize + 1);
        let s_iter = std::iter::successors(Some(p), |x| Some(x.wrapping_add(&q))).take(t);

        SLArrays {
            s_arr: s_iter.collect(),
            l_arr: l_iter.collect(),
        }
    }

    fn mix_sl_arrays(sl_arrays: SLArrays<T>) -> RC5<T> {
        let SLArrays { s_arr, l_arr } = sl_arrays;
        let total_loop_count = 3 * max(s_arr.len(), l_arr.len());
        let chunk_size = min(s_arr.len(), l_arr.len());

        let mut s_chunker = CircularArrayChunker::new(s_arr, chunk_size);
        let mut l_chunker = CircularArrayChunker::new(l_arr, chunk_size);

        let mut a = T::zero();
        let mut b = T::zero();
        for current_chunk_size in chunk_size_iter(total_loop_count, chunk_size) {
            std::iter::zip(s_chunker.next_chunk_mut(), l_chunker.next_chunk_mut())
                .take(current_chunk_size)
                .for_each(|(si, li)| {
                    // A = S[i] = (S[i] + A + B) << 3
                    *si = si.wrapping_add(&a).wrapping_add(&b).rotate_left(3);
                    a = *si;
                    // B = L[i] = (L[i] + A + B) << (A + B)
                    let ab = a.wrapping_add(&b);
                    *li = li.wrapping_add(&ab).rotate_left(ab);
                    b = *li;
                });
        }

        let s_arr = s_chunker.release_arr();
        // first 2 elements S[0] & S[1] are always present because of t = 2 + r*2
        let ([s0, s1], rest) = s_arr.split_array_ref();

        RC5 {
            s_arr: rest.array_chunks().copied().collect(),
            s0: *s0,
            s1: *s1,
        }
    }

    /// Encrypts the two-word block represented by the references `a` and `b`.
    ///
    /// The `a` and `b` parameters are mutable references to the two words (of type `T`)
    /// to be encrypted. The encrypted values are written back to the same references.
    ///
    /// # Examples
    ///
    /// ```
    /// use rc5::{RC5, RC5InitError};
    ///
    /// # fn main() -> Result<(), RC5InitError> {
    /// let key = b"my secret key";
    /// let rc5 = RC5::<u32>::new(12, key)?;
    ///
    /// let mut a = 0x12345678;
    /// let mut b = 0x9ABCDEF0;
    ///
    /// rc5.encrypt_words(&mut a, &mut b);
    ///
    /// assert_eq!(a, 0x4907F9B8);
    /// assert_eq!(b, 0x3F53A579);
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt_words(&self, a: &mut T, b: &mut T) {
        *a = a.wrapping_add(&self.s0);
        *b = b.wrapping_add(&self.s1);

        for [sa, sb] in self.s_arr.iter() {
            // A = A ^ B << B + S[2*i]
            // B = B ^ A << A + S[2*i + 1]
            *a = (*a ^ *b).rotate_left(*b).wrapping_add(sa);
            *b = (*b ^ *a).rotate_left(*a).wrapping_add(sb);
        }
    }

    /// Encrypts the two-word block represented by the references `a_bytes` and `b_bytes`.
    ///
    /// The `a_bytes` and `b_bytes` parameters are mutable references to the two words (of type
    /// `[u8; std::mem::size_of::<T>()]`)
    /// to be encrypted. The encrypted values are written back to the same array references.
    ///
    /// # Examples
    ///
    /// ```
    /// use rc5::{RC5, RC5InitError};
    ///
    /// # fn main() -> Result<(), RC5InitError> {
    /// let key = b"my secret key";
    /// let rc5 = RC5::<u32>::new(12, key)?;
    ///
    /// let mut a_bytes = [0x78, 0x56, 0x34, 0x12];
    /// let mut b_bytes = [0xF0, 0xDE, 0xBC, 0x9A];
    ///
    /// rc5.encrypt_word_bytes(&mut a_bytes, &mut b_bytes);
    ///
    /// assert_eq!(a_bytes, [0xB8, 0xF9, 0x07, 0x49]);
    /// assert_eq!(b_bytes, [0x79, 0xA5, 0x53, 0x3F]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt_word_bytes(
        &self,
        a_bytes: &mut [u8; std::mem::size_of::<T>()],
        b_bytes: &mut [u8; std::mem::size_of::<T>()],
    ) {
        let mut a = T::from_le_bytes(*a_bytes);
        let mut b = T::from_le_bytes(*b_bytes);

        self.encrypt_words(&mut a, &mut b);

        a_bytes.copy_from_slice(&a.to_le_bytes());
        b_bytes.copy_from_slice(&b.to_le_bytes());
    }

    /// Encrypts the two-word block represented by the reference `bytes`.
    ///
    /// The `bytes` parameter is a mutable reference to the two words (of type
    /// `[u8; std::mem::size_of::<T>() * NUM_WORDS_PER_BLOCK]`)
    /// to be encrypted. The encrypted values are written back to the same array reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use rc5::{RC5, RC5InitError};
    ///
    /// # fn main() -> Result<(), RC5InitError> {
    /// let key = b"my secret key";
    /// let rc5 = RC5::<u32>::new(12, key)?;
    ///
    /// let mut bytes = [0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A];
    ///
    /// rc5.encrypt_block(&mut bytes);
    ///
    /// assert_eq!(bytes, [0xB8, 0xF9, 0x07, 0x49, 0x79, 0xA5, 0x53, 0x3F]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt_block(&self, bytes: &mut [u8; std::mem::size_of::<T>() * NUM_WORDS_PER_BLOCK]) {
        let (a_bytes, b_bytes) = split_in_half_mut_ref::<u8, { std::mem::size_of::<T>() }>(bytes);
        self.encrypt_word_bytes(a_bytes, b_bytes);
    }

    /// Decrypts the two-word block represented by the references `a` and `b`.
    ///
    /// The `a` and `b` parameters are mutable references to the two words (of type `T`)
    /// to be decrypted. The decrypted values are written back to the same references.
    ///
    /// # Examples
    ///
    /// ```
    /// use rc5::{RC5, RC5InitError};
    ///
    /// # fn main() -> Result<(), RC5InitError> {
    /// let key = b"my secret key";
    /// let rc5 = RC5::<u32>::new(12, key)?;
    ///
    /// let mut a = 0x4907F9B8;
    /// let mut b = 0x3F53A579;
    ///
    /// rc5.decrypt_words(&mut a, &mut b);
    ///
    /// assert_eq!(a, 0x12345678);
    /// assert_eq!(b, 0x9ABCDEF0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_words(&self, a: &mut T, b: &mut T) {
        for [sa, sb] in self.s_arr.iter().rev() {
            // B = ((B - S[2*i+1]) >> A) ^ A
            *b = b.wrapping_sub(sb).rotate_right(*a) ^ *a;
            // A = ((A - S[2*i]) >> B) ^ B
            *a = a.wrapping_sub(sa).rotate_right(*b) ^ *b;
        }

        *b = b.wrapping_sub(&self.s1);
        *a = a.wrapping_sub(&self.s0);
    }

    /// Decrypts the two-word block represented by the references `a_bytes` and `b_bytes`.
    ///
    /// The `a_bytes` and `b_bytes` parameters are mutable references to the two words (of type
    /// `[u8; std::mem::size_of::<T>()]`)
    /// to be decrypted. The decrypted values are written back to the same array references.
    ///
    /// # Examples
    ///
    /// ```
    /// use rc5::{RC5, RC5InitError};
    ///
    /// # fn main() -> Result<(), RC5InitError> {
    /// let key = b"my secret key";
    /// let rc5 = RC5::<u32>::new(12, key)?;
    ///
    /// let mut a_bytes = [0xB8, 0xF9, 0x07, 0x49];
    /// let mut b_bytes = [0x79, 0xA5, 0x53, 0x3F];
    ///
    /// rc5.decrypt_word_bytes(&mut a_bytes, &mut b_bytes);
    ///
    /// assert_eq!(a_bytes, [0x78, 0x56, 0x34, 0x12]);
    /// assert_eq!(b_bytes, [0xF0, 0xDE, 0xBC, 0x9A]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_word_bytes(
        &self,
        a_bytes: &mut [u8; std::mem::size_of::<T>()],
        b_bytes: &mut [u8; std::mem::size_of::<T>()],
    ) {
        let mut a = T::from_le_bytes(*a_bytes);
        let mut b = T::from_le_bytes(*b_bytes);

        self.decrypt_words(&mut a, &mut b);

        a_bytes.copy_from_slice(&a.to_le_bytes());
        b_bytes.copy_from_slice(&b.to_le_bytes());
    }

    /// Decrypts the two-word block represented by the reference `bytes`.
    ///
    /// The `bytes` parameter is a mutable reference to the two words (of type
    /// `[u8; std::mem::size_of::<T>() * NUM_WORDS_PER_BLOCK]`)
    /// to be decrypted. The decrypted values are written back to the same array reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use rc5::{RC5, RC5InitError};
    ///
    /// # fn main() -> Result<(), RC5InitError> {
    /// let key = b"my secret key";
    /// let rc5 = RC5::<u32>::new(12, key)?;
    ///
    /// let mut bytes = [0xB8, 0xF9, 0x07, 0x49, 0x79, 0xA5, 0x53, 0x3F];
    ///
    /// rc5.decrypt_block(&mut bytes);
    ///
    /// assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_block(&self, bytes: &mut [u8; std::mem::size_of::<T>() * NUM_WORDS_PER_BLOCK]) {
        let (a_bytes, b_bytes) = split_in_half_mut_ref::<u8, { std::mem::size_of::<T>() }>(bytes);
        self.decrypt_word_bytes(a_bytes, b_bytes);
    }
}

fn pw<T: num_traits::Unsigned + FromU64>() -> T {
    let width = std::mem::size_of::<T>() * BITS_IN_BYTE;
    // ODD((E - 2) * (1 << w))
    // constant for 64bit
    const P: u64 = 0xB7E151628AED2A6B;
    let p = P >> (64 - width);
    T::from_u64(p | 1)
}

fn qw<T: num_traits::Unsigned + FromU64>() -> T {
    let width = std::mem::size_of::<T>() * BITS_IN_BYTE;
    // ODD((PHI - 1) * (1 << w))
    // constant for 64bit
    const Q: u64 = 0x9E3779B97F4A7C15;
    let q = Q >> (64 - width);
    T::from_u64(q | 1)
}

/// The `RC5InitError` enum represents the possible errors that can occur during the
/// [RC5] initialization
#[derive(thiserror::Error, Debug)]
pub enum RC5InitError {
    #[error("invalid key size: `{0}`; supported range is [0, {MAX_KEY_SIZE}]")]
    InvalidKeySize(usize),
}

/// Module containing functions for creating dynamic [RC5] algorithms using the [rc5_dyn::RC5Algo] trait,
/// from runtime width values or a control block.
pub mod rc5_dyn {
    use super::BITS_IN_BYTE;
    use super::MAX_KEY_SIZE;
    use super::NUM_WORDS_PER_BLOCK;

    /// The `RC5AlgoError` enum represents the possible errors that can occur during the
    /// encryption decryption in [RC5Algo].
    #[derive(thiserror::Error, Debug)]
    pub enum RC5AlgoError {
        #[error("invalid input block size, expected `{NUM_WORDS_PER_BLOCK} * {0}` sized block")]
        InvalidBlockSize(usize),
    }

    /// The `RC5Algo` trait provides methods for encrypting and decrypting data using
    /// the RC5 block cipher algorithm. This trait is useful when the RC5 algorithm needs
    /// to be constructed with a block size that is determined at runtime.
    pub trait RC5Algo {
        /// Encrypts the given slice of bytes in place using the RC5 block cipher algorithm.
        ///
        /// Returns a reference to the encrypted bytes on success, or an [RC5AlgoError] if
        /// the encryption failed.
        fn encrypt<'a>(&self, bytes: &'a mut [u8]) -> Result<&'a mut [u8], RC5AlgoError>;

        /// Decrypts the given slice of bytes in place using the RC5 block cipher algorithm.
        ///
        /// Returns a reference to the decrypted bytes on success, or an [RC5AlgoError] if
        /// the decryption failed.
        fn decrypt<'a>(&self, bytes: &'a mut [u8]) -> Result<&'a mut [u8], RC5AlgoError>;

        /// Return the block size of the algorithm
        fn block_size(&self) -> usize;
    }

    impl<T> RC5Algo for super::RC5<T>
    where
        T: num_traits::Unsigned
            + super::FromToLeBytes<T>
            + super::FromU64
            + num_traits::WrappingAdd
            + num_traits::WrappingSub
            + std::marker::Copy
            + std::ops::BitXor<T, Output = T>
            + super::BitRotabable<T, Output = T>
            + super::BitRotabable<u32, Output = T>,
        [u8; std::mem::size_of::<T>()]:,
        [u8; std::mem::size_of::<T>() * NUM_WORDS_PER_BLOCK]:,
    {
        fn encrypt<'a>(&self, bytes: &'a mut [u8]) -> Result<&'a mut [u8], RC5AlgoError> {
            self.encrypt_block(&mut *try_into_two_word_sized::<T>(bytes)?);
            Ok(bytes)
        }

        fn decrypt<'a>(&self, bytes: &'a mut [u8]) -> Result<&'a mut [u8], RC5AlgoError> {
            self.decrypt_block(&mut *try_into_two_word_sized::<T>(bytes)?);
            Ok(bytes)
        }

        fn block_size(&self) -> usize {
            std::mem::size_of::<T>() * NUM_WORDS_PER_BLOCK
        }
    }

    fn try_into_two_word_sized<T>(
        bytes: &mut [u8],
    ) -> Result<&mut [u8; std::mem::size_of::<T>() * NUM_WORDS_PER_BLOCK], RC5AlgoError>
    where
        T: num_traits::Unsigned + super::FromToLeBytes<T>,
        [u8; std::mem::size_of::<T>()]:,
    {
        bytes
            .try_into()
            .map_err(|_| RC5AlgoError::InvalidBlockSize(std::mem::size_of::<T>()))
    }

    /// The `RC5DynInitError` enum represents the possible errors that can occur during the
    /// [super::RC5] initialization with runtime width using [new]
    #[derive(thiserror::Error, Debug)]
    pub enum RC5DynInitError {
        #[error("invalid width `{0}`; supported widths are: {{16, 32, 64}}")]
        InvalidWidth(usize),
        #[error("invalid key size: `{0}`; supported range is [0, {MAX_KEY_SIZE}]")]
        InvalidKeySize(usize),
    }

    impl From<super::RC5InitError> for RC5DynInitError {
        fn from(value: super::RC5InitError) -> Self {
            match value {
                super::RC5InitError::InvalidKeySize(size) => RC5DynInitError::InvalidKeySize(size),
            }
        }
    }

    /// Constructs a new [super::RC5] encryption algorithm instance with dynamic width, key size and repetition count.
    ///
    /// # Arguments
    ///
    /// * width - The bit width of the word size to be used in the algorithm (16, 32, or 64).
    /// * repetitions - The number of rounds of encryption to be performed by the algorithm.
    /// * key - A slice of bytes representing the key to be used for encryption.
    ///
    /// # Returns
    ///
    /// A Result containing a boxed dyn [RC5Algo] instance on success, or a [RC5DynInitError] on failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use rc5::*;
    ///
    /// let key = b"my secret key";
    /// let algo = rc5_dyn::new(32, 12, key).unwrap();
    /// let pt_org = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    /// let mut pt = pt_org.clone();
    /// let mut ct = algo.encrypt(&mut pt).unwrap();
    /// assert_ne!(pt_org, ct);
    /// let decrypted = algo.decrypt(&mut ct).unwrap();
    /// assert_eq!(pt_org, decrypted);
    /// ````
    pub fn new(
        width: usize,
        repetitions: u8,
        key: &[u8],
    ) -> Result<Box<dyn RC5Algo>, RC5DynInitError> {
        const W16: usize = std::mem::size_of::<u16>() * BITS_IN_BYTE;
        const W32: usize = std::mem::size_of::<u32>() * BITS_IN_BYTE;
        const W64: usize = std::mem::size_of::<u64>() * BITS_IN_BYTE;
        match width {
            W16 => Ok(Box::new(super::RC5::<u16>::new(repetitions, key)?)),
            W32 => Ok(Box::new(super::RC5::<u32>::new(repetitions, key)?)),
            W64 => Ok(Box::new(super::RC5::<u64>::new(repetitions, key)?)),
            _ => Err(RC5DynInitError::InvalidWidth(width)),
        }
    }

    const CONTROL_BLOCK_HEADER_LEN: usize = 4;
    const VERSION_1_0: u8 = 0x10;

    /// The `RC5DynInitError` enum represents the possible errors that can occur during the
    /// [super::RC5] initialization with runtime width using [new]
    #[derive(thiserror::Error, Debug)]
    pub enum RC5DynControlBlockInitError {
        #[error("invalid control block length `{0}`; should be at least {CONTROL_BLOCK_HEADER_LEN} bytes long")]
        InvalidControlBlockLength(usize),
        #[error(
            "unsupported rc5 algorithm version `{0}`; the only supported version is {VERSION_1_0}"
        )]
        UnsupportedRC5Version(u8),
        #[error("specified key length `{0}` does not corespond to the provided key `{1}`")]
        InvalidControlBlockKeyLength(u8, usize),
        #[error("invalid width `{0}`; supported widths are: {{16, 32, 64}}")]
        InvalidWidth(usize),
        #[error("invalid key size: `{0}`; supported range is [0, {MAX_KEY_SIZE}]")]
        InvalidKeySize(usize),
    }

    impl From<RC5DynInitError> for RC5DynControlBlockInitError {
        fn from(value: RC5DynInitError) -> Self {
            match value {
                RC5DynInitError::InvalidWidth(size) => {
                    RC5DynControlBlockInitError::InvalidWidth(size)
                }
                RC5DynInitError::InvalidKeySize(size) => {
                    RC5DynControlBlockInitError::InvalidKeySize(size)
                }
            }
        }
    }
    /// Constructs a new [super::RC5] encryption algorithm instance from a rc5 control block
    ///
    /// # Arguments
    ///
    /// * control_block - The control block bytes, minimum length 4
    ///
    /// # Returns
    ///
    /// A Result containing a boxed dyn [RC5Algo] instance on success, or a [RC5DynControlBlockInitError] on failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use rc5::*;
    ///
    /// let control_block = [
    ///     0x10, 0x20, 0x0C, 0x0A, 0x20, 0x33, 0x7D, 0x83, 0x05, 0x5F, 0x62, 0x51, 0xBB, 0x09
    /// ];
    /// let algo = rc5_dyn::from_control_block(&control_block).unwrap();
    /// let pt_org = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    /// let mut pt = pt_org.clone();
    /// let mut ct = algo.encrypt(&mut pt).unwrap();
    /// assert_ne!(pt_org, ct);
    /// let decrypted = algo.decrypt(&mut ct).unwrap();
    /// assert_eq!(pt_org, decrypted);
    /// ````
    pub fn from_control_block(
        control_block: &[u8],
    ) -> Result<Box<dyn RC5Algo>, RC5DynControlBlockInitError> {
        if control_block.len() < CONTROL_BLOCK_HEADER_LEN {
            return Err(RC5DynControlBlockInitError::InvalidControlBlockLength(
                control_block.len(),
            ));
        }

        let ([version, width, repetitions, key_len], key) = control_block.split_array_ref();

        if *version != VERSION_1_0 {
            return Err(RC5DynControlBlockInitError::UnsupportedRC5Version(*version));
        }

        if *key_len as usize != key.len() {
            return Err(RC5DynControlBlockInitError::InvalidControlBlockKeyLength(
                *key_len,
                key.len(),
            ));
        }

        Ok(new(*width as usize, *repetitions, key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::rc5_dyn::*;
    use super::*;

    #[test]
    fn invalid_key_size_32() {
        let repetitions = 12;
        let key = [0; MAX_KEY_SIZE + 1];
        let res = RC5::<u32>::new(repetitions, &key);

        assert!(matches!(
            res,
            Err(RC5InitError::InvalidKeySize(error_key_size))
            if error_key_size == key.len()
        ));
    }

    #[test]
    fn invalid_key_size() {
        let width = 32;
        let repetitions = 12;
        let key = [0; MAX_KEY_SIZE + 1];
        let res = rc5_dyn::new(width, repetitions, &key);

        assert!(matches!(
            res,
            Err(RC5DynInitError::InvalidKeySize(error_key_size))
            if error_key_size == key.len()
        ));
    }

    #[test]
    fn invalid_width() {
        let width = 123;
        let repetitions = 12;
        let key = [1, 2, 3, 4];
        let res = new(width, repetitions, &key);

        assert!(matches!(
            res,
            Err(RC5DynInitError::InvalidWidth(error_width))
            if error_width == width
        ));
    }

    #[test]
    fn invalid_control_bloc_len() {
        let version = 0x10;
        let width = 32;
        let control_block = [version, width, 0x0C];
        let res = rc5_dyn::from_control_block(&control_block);
        assert!(matches!(
            res,
            Err(RC5DynControlBlockInitError::InvalidControlBlockLength(error_cb_len))
            if error_cb_len == control_block.len()
        ));
    }

    #[test]
    fn invalid_control_bloc_version() {
        let version = 0x11;
        let width = 32;
        let control_block = [
            version, width, 0x0C, 0x0A, 0x20, 0x33, 0x7D, 0x83, 0x05, 0x5F, 0x62, 0x51, 0xBB, 0x09,
        ];
        let res = rc5_dyn::from_control_block(&control_block);
        assert!(matches!(
            res,
            Err(RC5DynControlBlockInitError::UnsupportedRC5Version(error_version))
            if error_version == version
        ));
    }

    #[test]
    fn invalid_control_bloc_key_len() {
        let version = 0x10;
        let width = 32;
        let key_len = 8;
        let control_block = [
            version, width, 0x0C, key_len, 0x20, 0x33, 0x7D, 0x83, 0x05, 0x5F, 0x62, 0x51, 0xBB,
        ];
        let res = rc5_dyn::from_control_block(&control_block);
        assert!(matches!(
            res,
            Err(RC5DynControlBlockInitError::InvalidControlBlockKeyLength(error_b, error_key_len))
            if error_b == key_len && error_key_len == control_block.len() - 4
        ));
    }

    #[test]
    fn invalid_width_control_bloc() {
        let version = 0x10;
        let width = 123;
        let control_block = [
            version, width, 0x0C, 0x0A, 0x20, 0x33, 0x7D, 0x83, 0x05, 0x5F, 0x62, 0x51, 0xBB, 0x09,
        ];
        let res = rc5_dyn::from_control_block(&control_block);
        assert!(matches!(
            res,
            Err(RC5DynControlBlockInitError::InvalidWidth(error_width))
            if error_width == width as usize
        ));
    }

    #[test]
    fn control_block_init_ok() {
        let version = 0x10;
        let width = 32;
        let control_block = [
            version, width, 0x0C, 0x0A, 0x20, 0x33, 0x7D, 0x83, 0x05, 0x5F, 0x62, 0x51, 0xBB, 0x09,
        ];
        let res = rc5_dyn::from_control_block(&control_block);
        assert!(
            matches!(res, Ok(rc5) if rc5.block_size() == (width as usize / BITS_IN_BYTE * NUM_WORDS_PER_BLOCK))
        );
    }

    #[test]
    fn invalid_block_size_encrypt() {
        const WIDTH: usize = 16;
        let repetitions = 12;
        let key = [1, 2, 3, 4];
        let res = rc5_dyn::new(WIDTH, repetitions, &key);
        assert!(res.is_ok());

        if let Ok(rc5) = res {
            const INVALID_BLOCK_SIZE: usize = WIDTH / BITS_IN_BYTE * 3;
            const EXPECTED_WORD_SIZE: usize = WIDTH / BITS_IN_BYTE;
            let mut pt = [0; INVALID_BLOCK_SIZE];
            let res = rc5.encrypt(&mut pt);

            assert!(matches!(
                res,
                Err(RC5AlgoError::InvalidBlockSize(error_word_size))
                if error_word_size == EXPECTED_WORD_SIZE
            ));
        }
    }

    #[test]
    fn invalid_block_size_decrypt() {
        const WIDTH: usize = 16;
        let repetitions = 12;
        let key = [1, 2, 3, 4];
        let res = rc5_dyn::new(WIDTH, repetitions, &key);
        assert!(res.is_ok());

        if let Ok(rc5) = res {
            const INVALID_BLOCK_SIZE: usize = WIDTH / BITS_IN_BYTE * 3;
            const EXPECTED_WORD_SIZE: usize = WIDTH / BITS_IN_BYTE;
            let mut pt = [0; INVALID_BLOCK_SIZE];
            let res = rc5.decrypt(&mut pt);

            assert!(matches!(
                res,
                Err(RC5AlgoError::InvalidBlockSize(error_word_size))
                if error_word_size == EXPECTED_WORD_SIZE
            ));
        }
    }

    #[test]
    fn encode_a() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let mut pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = [0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let repetitions = 12;
        let rc5 = RC5::<u32>::new(repetitions, &key).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
        let key = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let mut pt = [0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = [0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let repetitions = 12;
        let rc5 = RC5::<u32>::new(repetitions, &key).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let mut ct = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let repetitions = 12;
        let rc5 = RC5::<u32>::new(repetitions, &key).unwrap();
        let res = RC5Algo::decrypt(&rc5, &mut ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
        let key = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = [0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let mut ct = [0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let repetitions = 12;
        let rc5 = RC5::<u32>::new(repetitions, &key).unwrap();
        let res = RC5Algo::decrypt(&rc5, &mut ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }
    #[test]
    fn encode_16_16_8() {
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut pt = [0x00, 0x01, 0x02, 0x03];
        let ct = [0x23, 0xA8, 0xD7, 0x2E];
        let repetitions = 16;
        let rc5 = RC5::<u16>::new(repetitions, &key).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_16_16_8() {
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let pt = [0x00, 0x01, 0x02, 0x03];
        let mut ct = [0x23, 0xA8, 0xD7, 0x2E];
        let repetitions = 16;
        let rc5 = RC5::<u16>::new(repetitions, &key).unwrap();
        let res = RC5Algo::decrypt(&rc5, &mut ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn encode_32_20_16() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let mut pt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let ct = [0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73];
        let repetitions = 20;
        let rc5 = RC5::<u32>::new(repetitions, &key).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_32_20_16() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut ct = [0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73];
        let repetitions = 20;
        let rc5 = RC5::<u32>::new(repetitions, &key).unwrap();
        let res = RC5Algo::decrypt(&rc5, &mut ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn encode_64_24_24() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let mut pt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let ct = [
            0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71,
            0x78, 0xDA,
        ];
        let repetitions = 24;
        let rc5 = RC5::<u64>::new(repetitions, &key).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_64_24_24() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let pt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let mut ct = [
            0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71,
            0x78, 0xDA,
        ];
        let repetitions = 24;
        let rc5 = RC5::<u64>::new(repetitions, &key).unwrap();
        let res = RC5Algo::decrypt(&rc5, &mut ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn encode_0_sized_key() {
        let key = [];
        let mut pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = [0x19, 0x4C, 0x67, 0x60, 0x57, 0xC3, 0x3F, 0xBE];
        let repetitions = 12;
        let rc5 = RC5::<u32>::new(repetitions, &key).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_0_repetitions() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let mut pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = [0x63, 0x55, 0x31, 0x9D, 0x13, 0x2A, 0xFF, 0x61];
        let repetitions = 0;
        let rc5 = RC5::<u32>::new(repetitions, &key).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_0_repetitions_and_key() {
        let key = [];
        let mut pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = [0x7A, 0x8C, 0xDC, 0x80, 0xBD, 0x66, 0x83, 0x95];
        let repetitions = 0;
        let rc5 = RC5::<u32>::new(repetitions, &key).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }
}
