use crate::{cookie::Cookie, errno::BinaryCookieError, page::Page};
use std::{fs::File, io::Read};

pub struct BinaryCookiesReader {
    cookie_size: u32,
    bits_offset: usize,
    data: Vec<u8>,
    pages_size: Vec<u32>,
    pages_data: Vec<Page>,
    check_sum: [u8; 8],
}

impl BinaryCookiesReader {
    /// # BinaryCookiesReader - new
    ///
    /// need a .binarycookies file path to build, return a BinaryCookiesReader
    ///
    /// ## Arguments
    ///
    /// * `target` - type is String, .binarycookies file path
    ///
    /// ## Returns
    ///
    /// `Result<(), BinaryCookieError>`
    ///
    /// ## Examples
    ///
    /// ```rust
    /// let target_file_path: String = String::from("/Users/foo/Library/HTTPStorages/boo.binarycookies");
    /// let mut bc_decoder = BinaryCookiesReader::new(&target_file_path).unwrap();
    /// let _ = bc_decoder.decoder().unwrap();
    /// for page in bc_decoder.origin_pages():
    ///     for cookie in page.cookies():
    ///         println!("{} | {} | {}", cookie.name_str(), cookie.value_str(), cookie.http_only)
    /// ```

    pub fn new(target: &String) -> Result<Self, BinaryCookieError> {
        let mut target_file = File::open(target)?;
        let mut data = vec![];
        let _ = target_file.read_to_end(&mut data)?;
        Ok(Self {
            cookie_size: 0,
            bits_offset: 0,
            data,
            pages_size: vec![],
            pages_data: vec![],
            check_sum: [0; 8],
        })
    }

    /// # BinaryCookiesReader - from_vec
    ///
    /// need a Vec<u8> data to build
    ///
    /// ## Arguments
    ///
    /// * `target` - type is Vec<u8>, after read_binary...
    ///
    /// ## Returns
    ///
    /// `BinaryCookiesReader`
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use std::fs::File;
    ///
    /// let target_file_path: String = String::from("/Users/foo/Library/HTTPStorages/boo.binarycookies");
    /// let mut buf = Vec::new();
    /// let mut f = File::open(&target_file_path);
    /// let _ = f.read_to_end(&mut buf);
    /// let mut bc_decoder = BinaryCookiesReader::from_vec(&buf).unwrap();
    /// let _ = bc_decoder.decoder().unwrap();
    /// for page in bc_decoder.origin_pages():
    ///     for cookie in page.cookies():
    ///         println!("{} | {} | {}", cookie.name_str(), cookie.value_str(), cookie.http_only)
    /// ```

    pub fn from_vec(target: &Vec<u8>) -> Self {
        let mut data = Vec::<u8>::with_capacity(target.len());
        data.extend(target.iter());
        Self {
            cookie_size: 0,
            bits_offset: 0,
            data,
            pages_size: vec![],
            pages_data: vec![],
            check_sum: [0; 8],
        }
    }

    fn read4bits(&mut self) -> Result<[u8; 4], BinaryCookieError> {
        let mut bits: [u8; 4] = [0; 4];
        for i in 0..4 {
            if let Some(&value) = self.data.get(self.bits_offset + i) {
                bits[i] = value;
            } else {
                return Err(BinaryCookieError::InvalidIndexOverBounds);
            };
        }
        self.bits_offset += 4;
        return Ok(bits);
    }

    fn read8bits(&mut self) -> Result<[u8; 8], BinaryCookieError> {
        let mut bits: [u8; 8] = [0; 8];
        for i in 0..8 {
            if let Some(&value) = self.data.get(self.bits_offset + i) {
                bits[i] = value;
            } else {
                return Err(BinaryCookieError::InvalidIndexOverBounds);
            }
        }
        self.bits_offset += 8;
        return Ok(bits);
    }

    fn read_bits(&mut self, size: u32) -> Result<Vec<u8>, BinaryCookieError> {
        let cap = size as usize;
        let mut bits: Vec<u8> = Vec::with_capacity(cap);
        for i in 0..cap {
            if let Some(&value) = self.data.get(self.bits_offset + i) {
                bits.push(value);
            } else {
                return Err(BinaryCookieError::InvalidIndexOverBounds);
            }
        }
        self.bits_offset += cap;
        Ok(bits)
    }

    pub fn decode(&mut self) -> Result<(), BinaryCookieError> {
        let magic_signature = [99, 111, 111, 107];
        let next: [u8; 4] = self.read4bits()?;
        if next != magic_signature {
            return Err(BinaryCookieError::InvalidSignature);
        }
        let next: [u8; 4] = self.read4bits()?;
        self.cookie_size = u32::from_be_bytes(next);
        for _ in 0..self.cookie_size {
            let next: [u8; 4] = self.read4bits()?;
            self.pages_size.push(u32::from_be_bytes(next));
        }
        for _ in 0..self.cookie_size {
            let start_code = self.read4bits()?;
            if start_code != [0x00, 0x00, 0x01, 0x00] {
                return Err(BinaryCookieError::InvalidStartCode);
            };
            let length_info = self.read4bits()?;
            let length = u32::from_le_bytes(length_info) as usize;
            let mut offset: Vec<u32> = Vec::with_capacity(length);
            for _ in 0..length {
                let next: [u8; 4] = self.read4bits()?;
                let data = u32::from_le_bytes(next);
                offset.push(data);
            }
            let mut page = Page::new(length, offset);
            let end_code = self.read4bits()?;
            if end_code != [0x00, 0x00, 0x00, 0x00] {
                return Err(BinaryCookieError::EndCodeError);
            }
            for _ in 0..length {
                let mut cookie = Cookie::default();
                let next = self.read4bits()?;
                cookie.init_cookie_size(next);
                let next = self.read4bits()?;
                cookie.init_unknown_one(next);
                let next = self.read4bits()?;
                cookie.init_flags(next);
                let next = self.read4bits()?;
                cookie.init_unknown_two(next);
                let next = self.read4bits()?;
                cookie.init_domain_offset(next);
                let next = self.read4bits()?;
                cookie.init_name_offset(next);
                let next = self.read4bits()?;
                cookie.init_path_offset(next);
                let next = self.read4bits()?;
                cookie.init_value_offset(next);
                let next = self.read4bits()?;
                cookie.init_comment_offset(next);
                let next = self.read4bits()?;
                if !cookie.is_end_header(next) {
                    return Err(BinaryCookieError::EndHeaderCodeError);
                };
                let next = self.read8bits()?;
                cookie.init_page_expires(next);
                let next = self.read8bits()?;
                cookie.init_page_creation(next);
                if cookie.check_over_size() {
                    return Err(BinaryCookieError::DataOverSize);
                };
                let comment_size = cookie.page_comment_size();
                if comment_size > 0 {
                    let next = self.read_bits(comment_size)?;
                    cookie.init_comment(next);
                };
                let domain_size = cookie.page_domain_size();
                if domain_size > 0 {
                    let next = self.read_bits(domain_size)?;
                    cookie.init_domain(next)
                };
                let name_size = cookie.page_name_size();
                if name_size > 0 {
                    let next = self.read_bits(name_size)?;
                    cookie.init_name(next)
                };
                let path_size = cookie.page_path_size();
                if path_size > 0 {
                    let next = self.read_bits(path_size)?;
                    cookie.init_path(next);
                };
                let value_size = cookie.page_value_size();
                if value_size > 0 {
                    let next = self.read_bits(value_size)?;
                    cookie.init_value(next)
                };
                page.mut_cookies().push(cookie);
            }
            self.pages_data.push(page);
        }
        self.check_sum = self.read8bits()?;
        Ok(())
    }

    pub fn origin_pages(&mut self) -> &Vec<Page> {
        return &self.pages_data;
    }
}
