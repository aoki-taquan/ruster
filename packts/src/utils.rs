use core::mem::MaybeUninit;

// MaybeUninit<T>はデストラクタが呼ばれないため注意すること
//
pub struct ArrayVec<T, const N: usize> {
    data: [MaybeUninit<T>; N],
    len: usize,
}

impl<T, const N: usize> ArrayVec<T, N> {
    pub fn new() -> Self {
        ArrayVec {
            data: [const { MaybeUninit::<T>::uninit() }; N],
            len: 0,
        }
    }
}

impl<T, const N: usize> ArrayVec<T, N> {
    pub fn push(&mut self, value: T) -> Result<(), ()> {
        if self.len < N {
            self.data[self.len] = MaybeUninit::new(value);
            self.len += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len > 0 {
            self.len -= 1;
            Some(unsafe { self.data[self.len].assume_init_read() })
        } else {
            None
        }
    }
}

impl<T, const N: usize> ArrayVec<T, N> {
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.len {
            Some(unsafe { self.data[index].assume_init_ref() })
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index < self.len {
            Some(unsafe { self.data[index].assume_init_mut() })
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<T, const N: usize> core::ops::Index<usize> for ArrayVec<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

pub struct ArrayVecIter<'a, T, const N: usize> {
    array_vec: &'a ArrayVec<T, N>,
    index: usize,
}

impl<'a, T, const N: usize> Iterator for ArrayVecIter<'a, T, N> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        match self.array_vec.get(self.index) {
            Some(value) => {
                self.index += 1;
                Some(value)
            }
            None => None,
        }
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a ArrayVec<T, N> {
    type Item = &'a T;
    type IntoIter = ArrayVecIter<'a, T, N>;

    fn into_iter(self) -> Self::IntoIter {
        ArrayVecIter {
            array_vec: self,
            index: 0,
        }
    }
}

pub trait Len {
    fn len(&self) -> usize;
}
