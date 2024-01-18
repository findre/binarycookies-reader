### About Binarycookies-Reader  

binarycookies-cookies is a program for parsing .binarycookies files on mac os systems.

### github


### How to use
```rust
use std::{fs::File, io::Read};
use binary_cookies::BinaryCookiesReader;

fn main() {
    let mut target = File::open("/Users/foo/Library/HTTPStorages/boo.binarycookies").unwrap();
    let mut data = Vec::new();
    let _ = target.read_to_end(&mut data).unwrap();
    let mut d = BinaryCookiesReader::from_vec(&data);
    let _ = d.deocde().unwrap();
    for pages in d.origin_pages() {
        for cookie in pages.cookies() {
            println!("{} | {} | {} | {}", cookie.domian_str(), cookie.name_str(), cookie.value_str(), cookie.http_only);
        }
    }
}
```