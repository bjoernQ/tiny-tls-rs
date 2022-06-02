# Tiny-TLS Rust

Port of the code found in https://github.com/jvns/tiny-tls/ to Rust.

Resources
- https://github.com/jvns/tiny-tls/
- https://jvns.ca/blog/2022/03/23/a-toy-version-of-tls/
- https://tls13.ulfheim.net/

This implementation is `no-std` and `no-alloc` so for learning purposes the Go code is easier to understand.

Other than the Go implementation this connects to wwww.google.com and only receives and prints the first record of the response.

# This is a toy implementation!

- it doesn't check the server certificate 
- it only supports one cipher suite
