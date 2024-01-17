use crate::cookie::Cookie;

#[derive(Default, Debug)]
#[allow(unused)]
pub struct Page {
    length: usize,
    offset: Vec<u32>,
    cookies: Vec<Cookie>,
}

impl Page {

    pub fn new(length: usize, offset: Vec<u32>) -> Self {
        Self {
            length,
            offset,
            cookies: vec![]
        }
    }

    pub fn mut_cookies(&mut self) -> &mut Vec<Cookie> {
        return &mut self.cookies
    }

    pub fn cookies(&self) -> &Vec<Cookie> {
        return &self.cookies
    }

}