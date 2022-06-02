use std::io::Read as StreamRead;
use std::io::Write as StreamWrite;
use std::net::TcpStream;

use embedded_io::{
    blocking::{Read, Write},
    Io,
};
use rand_core::OsRng;
use tiny_tls::buffer::Buffer;
use tiny_tls::Session;

pub fn main() {
    env_logger::init();

    let stream = std::net::TcpStream::connect("www.google.com:443").unwrap();
    let io = InputOutput(stream);
    let mut rng = OsRng;
    let mut tls = Session::new(io, "www.google.com", &mut rng);

    tls.connect().unwrap();

    tls.send_data(Buffer::new_from_slice(
        b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
    ))
    .expect("Sending data failed");
    tls.receive_data().expect("Receiving session ticket failed"); // ignore session ticket
    let data = tls.receive_data().unwrap();
    println!("{}", unsafe { std::str::from_utf8_unchecked(data.slice()) });

    println!("that's it for now");
}

struct InputOutput(TcpStream);

#[derive(Debug)]
enum IoError {
    Other,
}

impl embedded_io::Error for IoError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl Io for InputOutput {
    type Error = IoError;
}

impl Read for InputOutput {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.read(buf).map_err(|_| IoError::Other)
    }
}

impl Write for InputOutput {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        log::info!("write {} bytes", buf.len());

        self.0.write(buf).map_err(|_| IoError::Other)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.flush().map_err(|_| IoError::Other)
    }
}
