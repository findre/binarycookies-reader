### About Binarycookies-Reader  
binarycookies is a library for decoding .binarycookies files from Safari or WebKit.  
   
The Safari cookies file, also known as the Safari binary cookies file (Cookies.binarycookies) format
     
More info: https://github.com/libyal/dtformats/blob/main/documentation/Safari%20Cookies.asciidoc
   
### Github
https://github.com/findre/binarycookies-reader

### About Errors
- InvalidIndexOverBounds: cover index out of bounds, format error, cookie version invalid?
- InvalidSignature: cookie file must start with 'cook' 
- InvalidStartCode: start code start with '[0x00, 0x00, 0x00, 0x00]'
- EndCodeError
- EndHeaderCodeError
- DataOverSize
- SystemIOError: when use 'new' fuction, cover io error
   
### How to use
#### 1. use 'from_vec' function
```rust
use std::{fs::File, io::Read};
use binary_cookies::BinaryCookiesReader;

fn main() {
    let mut target = File::open("/Users/foo/Library/HTTPStorages/boo.binarycookies").unwrap();
    let mut data = Vec::new();
    let _ = target.read_to_end(&mut data).unwrap();
    let mut d = BinaryCookiesReader::from_vec(&data);
    let _ = d.decode().unwrap();
    for pages in d.origin_pages() {
        for cookie in pages.cookies() {
            println!("{} | {} | {} | {}", cookie.domain_str(), cookie.name_str(), cookie.value_str(), cookie.http_only);
        }
    }
}
```

#### 2. use 'new' function
```rust
use binary_cookies::BinaryCookiesReader;

fn main() {
    let target = String::from("/Users/foo/Library/HTTPStorages/boo.binarycookies");
    let mut dec = BinaryCookiesReader::new(&target).unwrap();
    let _ = d.decode().unwrap();
    for pages in d.origin_pages() {
        for cookie in pages.cookies() {
            println!("{} | {} | {} | {}", cookie.domain_str(), cookie.name_str(), cookie.value_str(), cookie.http_only);
        }
    }
}
```