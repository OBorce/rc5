// Copyright (c) 2023 Boris Onchev (boris.oncev@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE or copy at http://www.boost.org/LICENSE_1_0.txt)

//! This module provides utilities for cyclically iterating over and mutating an array in equal-sized chunks,
//! and generating a sequence of chunk sizes for a given array length and chunk size.

use std::cmp::min;

/// A struct that represents an array that is chunked and cycled when it reaches the end.
///
/// The `CircularArrayChunker` struct consists of an array and a chunk size. It provides a method
/// called `next_chunk_mut()` that returns an mut iterator to a chunk of the array. When the end of the
/// array is reached, the `next_chunk_mut()` method cycles back to the beginning of the array and
/// continues iterating. This creates a circular behavior for the array, allowing for seamless
/// iteration over chunks of the array.
///
/// # Examples
///
/// ```ignore
/// let arr = [1, 2, 3];
/// let chunk_size = 2;
/// let mut chunker = CircularArrayChunker::new(arr.into(), chunk_size);
///
/// let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
/// assert_eq!(*chunk, [1, 2]);
///
/// let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
/// assert_eq!(*chunk, [3, 1]);
///
/// let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
/// assert_eq!(*chunk, [2, 3]);
///
/// let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
/// assert_eq!(*chunk, [1, 2]);
/// ```
pub struct CircularArrayChunker<T> {
    arr: Box<[T]>,
    chunk_size: usize,
    offset: usize,
}

impl<T> CircularArrayChunker<T> {
    /// Creates a new `CircularArrayChunker` instance with the given array and chunk size.
    /// As the returned chunks are mutable the maximum chunk_size is the len of the array.
    /// A chunk_size of 0 will return empty an empty iterator
    ///
    pub fn new(arr: Box<[T]>, chunk_size: usize) -> CircularArrayChunker<T> {
        let arr_len = arr.len();
        CircularArrayChunker {
            arr,
            chunk_size: min(chunk_size, arr_len),
            offset: 0,
        }
    }

    /// Returns an iterator to the next chunk of the array.
    ///
    /// When the end of the array is reached, the returned iterator cycles back to the beginning
    /// of the array and continues iterating.
    pub fn next_chunk_mut(&mut self) -> impl Iterator<Item = &mut T> {
        let len = self.arr.len();
        let (left, right) = self.arr.split_at_mut(self.offset);
        self.offset = (self.offset + self.chunk_size) % len;
        right.iter_mut().chain(left).take(self.chunk_size)
    }

    /// Releases the array back for consumption
    pub fn release_arr(self) -> Box<[T]> {
        self.arr
    }
}

/// Returns an iterator that generates a sequence of chunk sizes for an array of a given size.
///
/// The `chunk_size_iter` function takes two arguments: `size`, which represents the total size
/// of the array, and `chunk_size`, which represents the desired size of each chunk. It returns
/// an iterator that generates a sequence of chunk sizes that can be used to chunk the array into
/// equal-sized chunks (with the exception of the last chunk, which may be smaller).
///
/// # Examples
///
/// ```ignore
/// let size = 10;
/// let chunk_size = 3;
///
/// let mut iter = chunk_size_iter(size, chunk_size);
///
/// assert_eq!(iter.next(), Some(3));
/// assert_eq!(iter.next(), Some(3));
/// assert_eq!(iter.next(), Some(3));
/// assert_eq!(iter.next(), Some(1));
/// assert_eq!(iter.next(), None);
/// ```
pub fn chunk_size_iter(size: usize, chunk_size: usize) -> impl Iterator<Item = usize> {
    let mut remaining = size;

    std::iter::from_fn(move || {
        if chunk_size == 0 || remaining == 0 {
            None
        } else {
            let current_chunk_size = min(remaining, chunk_size);
            remaining -= current_chunk_size;
            Some(current_chunk_size)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_size_iter_10_3() {
        let mut iter = chunk_size_iter(10, 3);
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn chunk_size_bigger_than_size() {
        let mut iter = chunk_size_iter(3, 10);
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn chunk_size_0() {
        let mut iter = chunk_size_iter(3, 0);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn chunker_loop() {
        let arr = [1, 2, 3];
        let chunk_size = 2;
        let mut chunker = CircularArrayChunker::new(arr.into(), chunk_size);
        let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
        assert_eq!(*chunk, [1, 2]);

        let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
        assert_eq!(*chunk, [3, 1]);

        let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
        assert_eq!(*chunk, [2, 3]);

        let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
        assert_eq!(*chunk, [1, 2]);
    }

    #[test]
    fn chunker_loop_chunk_size_bigger_than_arr() {
        let arr = [1, 2, 3];
        let chunk_size = 5;
        let mut chunker = CircularArrayChunker::new(arr.into(), chunk_size);
        let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
        assert_eq!(*chunk, [1, 2, 3]);

        let chunk: Box<[i32]> = chunker.next_chunk_mut().map(|a| *a).collect();
        assert_eq!(*chunk, [1, 2, 3]);
    }

    #[test]
    fn chunker_loop_chunk_size_0() {
        let arr = [1, 2, 3];
        let chunk_size = 0;
        let mut chunker = CircularArrayChunker::new(arr.into(), chunk_size);
        let mut chunk = chunker.next_chunk_mut();
        assert_eq!(chunk.next(), None);
    }
}
