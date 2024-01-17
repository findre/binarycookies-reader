#[derive(Debug, Default)]
pub struct Cookie {
    pub secure: bool,
    pub http_only: bool,
	size: u32,
    flags: u32,
    domain_offset: u32,
    name_offset: u32,
    path_offset: u32,
    value_offset: u32,
    comment_offset: u32,
    expires: f64,
    creation: f64,
    unknown_one: [u8; 4],
	unknown_two: [u8; 4],
	value: Vec<u8>,
    name: Vec<u8>,
    comment: Vec<u8>,
    domain: Vec<u8>,
    path: Vec<u8>,
}

impl Cookie {
    
    pub fn init_cookie_size(&mut self, bits: [u8; 4]) {
        self.size = u32::from_le_bytes(bits);
    }
    
    pub fn init_unknown_one(&mut self, bits: [u8; 4]) {
        self.unknown_one = bits
    }

    pub fn init_flags(&mut self, bits: [u8; 4]) {
        let cookie_flags = u32::from_le_bytes(bits);
        self.flags = cookie_flags;
        if cookie_flags == 0x00 {
            self.secure = false;
            self.http_only = false;
        } else if cookie_flags == 0x01 {
            self.secure = true
        } else if cookie_flags == 0x04 {
            self.http_only = true;
        } else if cookie_flags == 0x05 {
            self.secure = true;
            self.http_only = true;
        }
    }

    pub fn init_unknown_two(&mut self, bits: [u8; 4]) {
        self.unknown_two = bits
    }

    pub fn init_domain_offset(&mut self, bits: [u8; 4]) {
        let offset = u32::from_le_bytes(bits);
        self.domain_offset = offset
    }

    pub fn init_name_offset(&mut self, bits: [u8; 4]) {
        let offset = u32::from_le_bytes(bits);
        self.name_offset = offset
    }

    pub fn init_path_offset(&mut self, bits: [u8; 4]) {
        let offset = u32::from_le_bytes(bits);
        self.path_offset = offset
    }

    pub fn init_value_offset(&mut self, bits: [u8; 4]) {
        let offset = u32::from_le_bytes(bits);
        self.value_offset = offset
    }

    pub fn init_comment_offset(&mut self, bits: [u8; 4]) {
        let offset = u32::from_le_bytes(bits);
        self.comment_offset = offset
    }

    pub fn is_end_header(&mut self, bits: [u8; 4]) -> bool {
        if bits == [0, 0, 0, 0] {
            return true;
        }
        return false
    }

    pub fn init_page_expires(&mut self, bits: [u8; 8]) {
        let time_padding: f64 = 978307200.0;
        let expire = f64::from_le_bytes(bits) + time_padding;
        self.expires = expire
    }

    pub fn init_page_creation(&mut self, bits: [u8; 8]) {
        let time_padding: f64 = 978307200.0;
        let creation = f64::from_le_bytes(bits) + time_padding;
        self.creation = creation
    }

    pub fn check_over_size(&mut self) -> bool {
        let mut total = 0;
        let check: [u32; 5] = [
            self.domain_offset - self.comment_offset,
            self.name_offset - self.domain_offset,
            self.path_offset - self.name_offset,
            self.value_offset - self.path_offset,
            self.size - self.value_offset
        ];
        for value in check {
            if value > 4096 {
                return true
            };
            total += value;
        };
        if total > 4096 {
            return true
        }
        return false
    }

    pub fn page_comment_size(&mut self) -> u32 {
        if self.comment_offset == 0 {
            return 0;
        };
        return self.domain_offset - self.comment_offset;
    }

    pub fn page_domain_size(&mut self) -> u32 {
        return self.name_offset - self.domain_offset;
    }

    pub fn page_name_size(&mut self) -> u32 {
        return self.path_offset - self.name_offset;
    }

    pub fn page_path_size(&mut self) -> u32 {
        return self.value_offset - self.path_offset;
    }

    pub fn page_value_size(&mut self) -> u32 {
        return self.size - self.value_offset;
    }

    pub fn init_comment(&mut self, comment: Vec<u8>) {
        self.comment = comment;
    }

    pub fn init_domain(&mut self, doamin: Vec<u8>) {
        self.domain = doamin;
    }

    pub fn init_name(&mut self, name: Vec<u8>) {
        self.name = name;
    }

    pub fn init_path(&mut self, path: Vec<u8>) {
        self.path = path;
    }

    pub fn init_value(&mut self, value: Vec<u8>) {
        self.value = value
    }

    pub fn domian_str(&self) -> String {
        String::from_utf8_lossy(&self.domain).trim_end_matches("\0").to_string()
    }

    pub fn value_str(&self) -> String {
        String::from_utf8_lossy(&self.value).trim_end_matches("\0").to_string()
    }

    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).trim_end_matches("\0").to_string()
    }

    pub fn comment_str(&self) -> String {
        String::from_utf8_lossy(&self.comment).trim_end_matches("\0").to_string()
    }

    pub fn path_str(&self) -> String {
        String::from_utf8_lossy(&self.path).trim_end_matches("\0").to_string()
    }

}
