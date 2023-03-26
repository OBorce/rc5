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

/// The RC5 struct represents an instance of the RC5 block cipher algorithm.
///
/// The `RC5` struct provides methods for initializing the algorithm with a key and
/// a number of rounds, as well as methods for encrypting and decrypting individual
/// words and blocks of data.
pub struct RC5<T> {
    //TODO: maybe add an allocator support
    s_arr: Box<[[T; 2]]>,
    s0: T,
    s1: T,
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
    /// let rc5 = RC5::<u32>::new(key, 12);
    /// ```
    pub fn new(key: &[u8], repetitions: u8) -> Result<RC5<T>, RC5InitError> {
        if key.len() > 255 {
            return Err(RC5InitError::InvalidKeySize(key.len()));
        }

        let (s_arr, l_arr) = RC5::init_sl_arrays(key, repetitions);

        Ok(RC5::mix_sl_arrays(s_arr, l_arr))
    }

    fn init_sl_arrays(key: &[u8], repetitions: u8) -> (Box<[T]>, Box<[T]>) {
        let p = pw::<T>();
        let q = qw::<T>();

        let t_num_bytes: usize = std::mem::size_of::<T>();
        let padding_size = (t_num_bytes - (key.len() % t_num_bytes)) % t_num_bytes;
        let padding = std::iter::repeat(0).take(padding_size);
        let l = key
            .iter()
            .copied()
            .chain(padding)
            .array_chunks()
            .map(T::from_le_bytes);

        let t = 2 * (repetitions as usize + 1);
        let s = std::iter::successors(Some(p), |x| Some(x.wrapping_add(&q))).take(t);

        (s.collect(), l.collect())
    }

    pub fn mix_sl_arrays(s_arr: Box<[T]>, l_arr: Box<[T]>) -> RC5<T> {
        let total_count = 3 * max(s_arr.len(), l_arr.len());
        let chunk_size = min(s_arr.len(), l_arr.len());

        let mut s_chunker = CircularArrayChunker::new(s_arr, chunk_size);
        let mut l_chunker = CircularArrayChunker::new(l_arr, chunk_size);

        let mut a = T::zero();
        let mut b = T::zero();
        for current_chunk_size in chunk_size_iter(total_count, chunk_size) {
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
    /// let rc5 = RC5::<u32>::new(key, 12)?;
    ///
    /// let mut a = 0x12345678;
    /// let mut b = 0x9ABCDEF0;
    ///
    /// rc5.encrypt_words(&mut a, &mut b);
    ///
    /// assert_eq!(a, 0x92F4D0C5);
    /// assert_eq!(b, 0xEB0088E3);
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt_words(&self, a: &mut T, b: &mut T) {
        *a = a.wrapping_add(&self.s0);
        *b = b.wrapping_add(&self.s1);

        for [s1, s2] in self.s_arr.iter() {
            // A = A ^ B << B + S[2*i]
            // B = B ^ A << A + S[2*i + 1]
            *a = (*a ^ *b).rotate_left(*b).wrapping_add(s1);
            *b = (*b ^ *a).rotate_left(*a).wrapping_add(s2);
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
    /// let rc5 = RC5::<u32>::new(key, 12)?;
    ///
    /// let mut a_bytes = [0x78, 0x56, 0x34, 0x12];
    /// let mut b_bytes = [0xF0, 0xDE, 0xBC, 0x9A];
    ///
    /// rc5.encrypt_block(&mut a_bytes, &mut b_bytes);
    ///
    /// assert_eq!(a_bytes, [0xC5, 0xD0, 0xF4, 0x92]);
    /// assert_eq!(b_bytes, [0xE3, 0x88, 0x00, 0xEB]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt_block(
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
    /// let rc5 = RC5::<u32>::new(key, 12)?;
    ///
    /// let mut a = 0x92F4D0C5;
    /// let mut b = 0xEB0088E3;
    ///
    /// rc5.decrypt_words(&mut a, &mut b);
    ///
    /// assert_eq!(a, 0x12345678);
    /// assert_eq!(b, 0x9ABCDEF0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_words(&self, a: &mut T, b: &mut T) {
        for [s1, s2] in self.s_arr.iter().rev() {
            // B = ((B - S[2*i+1]) >> A) ^ A
            *b = b.wrapping_sub(s2).rotate_right(*a) ^ *a;
            // A = ((A - S[2*i]) >> B) ^ B
            *a = a.wrapping_sub(s1).rotate_right(*b) ^ *b;
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
    /// let rc5 = RC5::<u32>::new(key, 12)?;
    ///
    /// let mut a_bytes = [0xC5, 0xD0, 0xF4, 0x92];
    /// let mut b_bytes = [0xE3, 0x88, 0x00, 0xEB];
    ///
    /// rc5.decrypt_block(&mut a_bytes, &mut b_bytes);
    ///
    /// assert_eq!(a_bytes, [0x78, 0x56, 0x34, 0x12]);
    /// assert_eq!(b_bytes, [0xF0, 0xDE, 0xBC, 0x9A]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_block(
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
}

/// The `RC5AlgoError` enum represents the possible errors that can occur during the
/// encryption decryption in [RC5Algo].
#[derive(thiserror::Error, Debug)]
pub enum RC5AlgoError {
    #[error(
        "invalid input block size, can't divide into 2 word size blocks, expected `2 * {0}` sized block"
    )]
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
}

impl<T> RC5Algo for RC5<T>
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
    fn encrypt<'a>(&self, bytes: &'a mut [u8]) -> Result<&'a mut [u8], RC5AlgoError> {
        let (a_bytes, b_bytes) = bytes.split_at_mut(bytes.len() / 2);

        self.encrypt_block(
            &mut *try_into_sized::<T>(a_bytes)?,
            &mut *try_into_sized::<T>(b_bytes)?,
        );

        Ok(bytes)
    }

    fn decrypt<'a>(&self, bytes: &'a mut [u8]) -> Result<&'a mut [u8], RC5AlgoError> {
        let (a_bytes, b_bytes) = bytes.split_at_mut(bytes.len() / 2);

        self.decrypt_block(
            &mut *try_into_sized::<T>(a_bytes)?,
            &mut *try_into_sized::<T>(b_bytes)?,
        );

        Ok(bytes)
    }
}

fn try_into_sized<T>(bytes: &mut [u8]) -> Result<&mut [u8; std::mem::size_of::<T>()], RC5AlgoError>
where
    T: num_traits::Unsigned + FromToLeBytes<T>,
    [u8; std::mem::size_of::<T>()]:,
{
    bytes
        .try_into()
        .map_err(|_| RC5AlgoError::InvalidBlockSize(std::mem::size_of::<T>()))
}

fn pw<T: num_traits::Unsigned + FromU64>() -> T {
    let width = std::mem::size_of::<T>() * 8;
    // ODD((E - 2) * (1 << w))
    // constant for 64bit
    const P: u64 = 0xB7E151628AED2A6B;
    let p = P >> (64 - width);
    T::from_u64(p | 1)
}

fn qw<T: num_traits::Unsigned + FromU64>() -> T {
    let width = std::mem::size_of::<T>() * 8;
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
    #[error("invalid key size: `{0}`; supported range is [0, 255]")]
    InvalidKeySize(usize),
}

/// The `RC5DynInitError` enum represents the possible errors that can occur during the
/// [RC5] initialization with runtime width using [new_rc5_dyn]
#[derive(thiserror::Error, Debug)]
pub enum RC5DynInitError {
    #[error("invalid width `{0}`; supported widths are: {{16, 32, 64}}")]
    InvalidWidth(usize),
    #[error("invalid key size: `{0}`; supported range is [0, 255]")]
    InvalidKeySize(usize),
}

impl From<RC5InitError> for RC5DynInitError {
    fn from(value: RC5InitError) -> Self {
        match value {
            RC5InitError::InvalidKeySize(size) => RC5DynInitError::InvalidKeySize(size),
        }
    }
}

/// Constructs a new [RC5] encryption algorithm instance with dynamic key size and repetition count.
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
/// use rc5::{new_rc5_dyn, RC5Algo};
///
/// let key = b"my secret key";
/// let algo = new_rc5_dyn(32, 12, key).unwrap();
/// let pt_org = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
/// let mut pt = pt_org.clone();
/// let mut ct = algo.encrypt(&mut pt).unwrap();
/// assert_ne!(pt_org, ct);
/// let decrypted = algo.decrypt(&mut ct).unwrap();
/// assert_eq!(pt_org, decrypted);
/// ````
pub fn new_rc5_dyn(
    width: usize,
    repetitions: u8,
    key: &[u8],
) -> Result<Box<dyn RC5Algo>, RC5DynInitError> {
    const W16: usize = std::mem::size_of::<u16>() * 8;
    const W32: usize = std::mem::size_of::<u32>() * 8;
    const W64: usize = std::mem::size_of::<u64>() * 8;
    match width {
        W16 => Ok(Box::new(RC5::<u16>::new(key, repetitions)?)),
        W32 => Ok(Box::new(RC5::<u32>::new(key, repetitions)?)),
        W64 => Ok(Box::new(RC5::<u64>::new(key, repetitions)?)),
        _ => Err(RC5DynInitError::InvalidWidth(width)),
    }
}

/// The `RC5DynInitError` enum represents the possible errors that can occur during the
/// [RC5] initialization with runtime width using [new_rc5_dyn]
#[derive(thiserror::Error, Debug)]
pub enum RC5DynControlBlockInitError {
    #[error("invalid control block length `{0}`; should be at least 4 bytes long")]
    InvalidControlBlockLength(usize),
    #[error("unsupported rc5 algorithm version `{0}`; the only supported version is 0x10")]
    UnsupportedRC5Version(u8),
    #[error("specified key length `{0}` does not corespond to the provided key `{1}`")]
    InvalidControlBlockKeyLength(u8, usize),
    #[error("invalid width `{0}`; supported widths are: {{16, 32, 64}}")]
    InvalidWidth(usize),
    #[error("invalid key size: `{0}`; supported range is [0, 255]")]
    InvalidKeySize(usize),
}

impl From<RC5DynInitError> for RC5DynControlBlockInitError {
    fn from(value: RC5DynInitError) -> Self {
        match value {
            RC5DynInitError::InvalidWidth(size) => RC5DynControlBlockInitError::InvalidWidth(size),
            RC5DynInitError::InvalidKeySize(size) => {
                RC5DynControlBlockInitError::InvalidKeySize(size)
            }
        }
    }
}
/// Constructs a new [RC5] encryption algorithm instance from a rc5 control block
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
/// use rc5::{new_rc5_dyn_from_control_block, RC5Algo};
///
/// let control_block = [
///     0x10, 0x20, 0x0C, 0x0A, 0x20, 0x33, 0x7D, 0x83, 0x05, 0x5F, 0x62, 0x51, 0xBB, 0x09
/// ];
/// let algo = new_rc5_dyn_from_control_block(&control_block).unwrap();
/// let pt_org = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
/// let mut pt = pt_org.clone();
/// let mut ct = algo.encrypt(&mut pt).unwrap();
/// assert_ne!(pt_org, ct);
/// let decrypted = algo.decrypt(&mut ct).unwrap();
/// assert_eq!(pt_org, decrypted);
/// ````
pub fn new_rc5_dyn_from_control_block(
    control_block: &[u8],
) -> Result<Box<dyn RC5Algo>, RC5DynControlBlockInitError> {
    if control_block.len() < 4 {
        return Err(RC5DynControlBlockInitError::InvalidControlBlockLength(
            control_block.len(),
        ));
    }

    let ([version, width, repetitions, key_len], key) = control_block.split_array_ref();

    if *version != 0x10 {
        return Err(RC5DynControlBlockInitError::UnsupportedRC5Version(*version));
    }

    if *key_len as usize != key.len() {
        return Err(RC5DynControlBlockInitError::InvalidControlBlockKeyLength(
            *key_len,
            key.len(),
        ));
    }

    Ok(new_rc5_dyn(*width as usize, *repetitions, key)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_key_size_32() {
        let repetitions = 12;
        let key = [0; 256];
        let res = RC5::<u32>::new(&key, repetitions);

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
        let key = [0; 256];
        let res = new_rc5_dyn(width, repetitions, &key);

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
        let res = new_rc5_dyn(width, repetitions, &key);

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
        let res = new_rc5_dyn_from_control_block(&control_block);
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
        let res = new_rc5_dyn_from_control_block(&control_block);
        assert!(matches!(
            res,
            Err(RC5DynControlBlockInitError::UnsupportedRC5Version(error_version))
            if error_version == version
        ));
    }

    #[test]
    fn invalid_width_control_bloc() {
        let version = 0x10;
        let width = 123;
        let control_block = [
            version, width, 0x0C, 0x0A, 0x20, 0x33, 0x7D, 0x83, 0x05, 0x5F, 0x62, 0x51, 0xBB, 0x09,
        ];
        let res = new_rc5_dyn_from_control_block(&control_block);
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
        let res = new_rc5_dyn_from_control_block(&control_block);
        assert!(matches!(res, Ok(_)));
    }

    #[test]
    fn invalid_block_size_encrypt() {
        const WIDTH: usize = 16;
        let repetitions = 12;
        let key = [1, 2, 3, 4];
        let res = new_rc5_dyn(WIDTH, repetitions, &key);
        assert!(res.is_ok());

        if let Ok(rc5) = res {
            const INVALID_BLOCK_SIZE: usize = WIDTH / 8 * 3;
            const EXPECTED_WORD_SIZE: usize = WIDTH / 8;
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
        let res = new_rc5_dyn(WIDTH, repetitions, &key);
        assert!(res.is_ok());

        if let Ok(rc5) = res {
            const INVALID_BLOCK_SIZE: usize = WIDTH / 8 * 3;
            const EXPECTED_WORD_SIZE: usize = WIDTH / 8;
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
        let rc5 = RC5::<u32>::new(&key, repetitions).unwrap();
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
        let rc5 = RC5::<u32>::new(&key, repetitions).unwrap();
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
        let rc5 = RC5::<u32>::new(&key, repetitions).unwrap();
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
        let rc5 = RC5::<u32>::new(&key, repetitions).unwrap();
        let res = RC5Algo::decrypt(&rc5, &mut ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }
    #[test]
    fn encode_16_16_8() {
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut pt = [0x00, 0x01, 0x02, 0x03];
        let ct = [0x23, 0xA8, 0xD7, 0x2E];
        let repetitions = 16;
        let rc5 = RC5::<u16>::new(&key, repetitions).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_16_16_8() {
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let pt = [0x00, 0x01, 0x02, 0x03];
        let mut ct = [0x23, 0xA8, 0xD7, 0x2E];
        let repetitions = 16;
        let rc5 = RC5::<u16>::new(&key, repetitions).unwrap();
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
        let rc5 = RC5::<u32>::new(&key, repetitions).unwrap();
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
        let rc5 = RC5::<u32>::new(&key, repetitions).unwrap();
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
        let rc5 = RC5::<u64>::new(&key, repetitions).unwrap();
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
        let rc5 = RC5::<u64>::new(&key, repetitions).unwrap();
        let res = RC5Algo::decrypt(&rc5, &mut ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn encode_0_sized_key() {
        let key = [];
        let mut pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = [0x7F, 0x1B, 0xA7, 0x16, 0x68, 0xFB, 0xB5, 0x96];
        let repetitions = 12;
        let rc5 = RC5::<u32>::new(&key, repetitions).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_0_repetitions() {
        let key = [];
        let mut pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = [0x63, 0x62, 0x03, 0xEB, 0x60, 0x20, 0x7F, 0xCD];
        let repetitions = 0;
        let rc5 = RC5::<u32>::new(&key, repetitions).unwrap();
        let res = RC5Algo::encrypt(&rc5, &mut pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }
}
