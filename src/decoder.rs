use crate::{
    page::Page, 
    cookie::Cookie, 
    errno::BinaryCookieError
};

pub struct BinaryCookiesReader {
    cookie_size: u32,
    bits_offset: usize,
    data: Vec<u8>,
    pages_size: Vec<u32>,
    pages_data: Vec<Page>,
    check_sum: [u8; 8],
}

impl BinaryCookiesReader {
    
    pub fn from_vec(target: &Vec<u8>) -> Self {
        let mut data = Vec::<u8>::with_capacity(target.len());
        data.extend(target.iter());
        Self {
            cookie_size: 0,
            bits_offset: 0,
            data,
            pages_size: vec![],
            pages_data: vec![],
            check_sum: [0; 8]
        }
    }

    fn read4bits(&mut self) -> [u8; 4] {
        let mut bits: [u8; 4] = [0; 4];
        for i in 0..4 {
            bits[i] = self.data[self.bits_offset + i]
        }
        self.bits_offset += 4;
        return bits
    }

    fn read8bits(&mut self) -> [u8; 8] {
        let mut bits: [u8; 8] = [0; 8];
        for i in 0..8 {
            bits[i] = self.data[self.bits_offset + i]
        }
        self.bits_offset += 8;
        return bits
    }

    fn read_bits(&mut self, size: u32) -> Vec<u8> {
        let cap = size as usize;
        let mut bits: Vec<u8> = Vec::with_capacity(cap);
        for i in 0..cap {
            bits.push(self.data[self.bits_offset+i])
        };
        self.bits_offset += cap;
        bits
    }

    pub fn deocde(&mut self) -> Result<(), BinaryCookieError> {
        let magic_signature = [99, 111, 111, 107];
        let next: [u8; 4] = self.read4bits();
        if next != magic_signature {
            return Err(BinaryCookieError::InvalidSignature)
        }
        let next: [u8; 4] = self.read4bits();
        self.cookie_size = u32::from_be_bytes(next);
        for _ in 0..self.cookie_size {
            let next: [u8; 4] = self.read4bits();
            self.pages_size.push(u32::from_be_bytes(next));
        }
        for _ in 0..self.cookie_size {
            let start_code = self.read4bits();
            if start_code != [0x00, 0x00, 0x01, 0x00] {
                return Err(BinaryCookieError::InvalidStartCode)
            };
            let length_info = self.read4bits();
            let length = u32::from_le_bytes(length_info) as usize;
            let mut offset: Vec<u32> = Vec::with_capacity(length);
            for _ in 0..length {
                let next: [u8; 4] = self.read4bits();
                let data = u32::from_le_bytes(next);
                offset.push(data);
            };
            let mut page = Page::new(length, offset);
            let end_code = self.read4bits();
            if end_code != [0x00, 0x00, 0x00, 0x00] {
                return Err(BinaryCookieError::EndCodeError);
            }
            for _ in 0..length {
                let mut cookie = Cookie::default();
                let next = self.read4bits();
                cookie.init_cookie_size(next);
                let next = self.read4bits();
                cookie.init_unknown_one(next);
                let next = self.read4bits();
                cookie.init_flags(next);
                let next = self.read4bits();
                cookie.init_unknown_two(next);
                let next = self.read4bits();
                cookie.init_domain_offset(next);
                let next = self.read4bits();
                cookie.init_name_offset(next);
                let next = self.read4bits();
                cookie.init_path_offset(next);
                let next = self.read4bits();
                cookie.init_value_offset(next);
                let next = self.read4bits();
                cookie.init_comment_offset(next);
                let next = self.read4bits();
                if !cookie.is_end_header(next) {
                    return Err(BinaryCookieError::EndHeaderCodeError);
                };
                let next = self.read8bits();
                cookie.init_page_expires(next);
                let next = self.read8bits();
                cookie.init_page_creation(next);
                if cookie.check_over_size() {
                    return Err(BinaryCookieError::DataOverSize);
                };
                let comment_size = cookie.page_comment_size();
                if comment_size > 0 {
                    let next = self.read_bits(comment_size);
                    cookie.init_comment(next);
                };
                let domain_size = cookie.page_domain_size();
                if domain_size > 0 {
                    let next = self.read_bits(domain_size);
                    cookie.init_domain(next)
                };
                let name_size = cookie.page_name_size();
                if name_size > 0 {
                    let next = self.read_bits(name_size);
                    cookie.init_name(next)
                };
                let path_size = cookie.page_path_size();
                if path_size > 0 {
                    let next = self.read_bits(path_size);
                    cookie.init_path(next);
                };
                let value_size = cookie.page_value_size();
                if value_size > 0 {
                    let next = self.read_bits(value_size);
                    cookie.init_value(next)
                };
                page.mut_cookies().push(cookie);
            };
            self.pages_data.push(page);
        };
        self.check_sum = self.read8bits();
        Ok(())
    }

    pub fn origin_pages(&mut self) -> &Vec<Page> {
        return &self.pages_data
    }
    
}