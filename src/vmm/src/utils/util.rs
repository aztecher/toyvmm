// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub use utils::errno;

pub fn get_page_size() -> Result<usize, errno::Error> {
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        -1 => Err(errno::Error::last()),
        ps => Ok(ps as usize),
    }
}

#[cfg(test)]
pub mod tests {
    use super::get_page_size;
    #[test]
    fn test_get_page_size() {
        let page_size = get_page_size().expect("Cannot retrieve page size");
        assert_eq!(4096, page_size);
    }
}
