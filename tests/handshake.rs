use embedded_io::{
    blocking::{Read, Write},
    Io,
};
use tiny_tls::{buffer::Buffer, Session};

const CLIENT_EPHEMERAL_PRIVATE: &str =
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const CLIENT_HELLO: &str = "16030100ca010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304";
const SERVER_HELLO: &str = "160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304";
const WRAPPER: &str = "1703030475da1ec2d7bda8ebf73edd5010fba8089fd426b0ea1ea4d88d074ffea8a9873af5f502261e34b1563343e9beb6132e7e836d65db6dcf00bc401935ae369c440d67af719ec03b984c4521b905d58ba2197c45c4f773bd9dd121b4d2d4e6adfffa27c2a81a99a8efe856c35ee08b71b3e441bbecaa65fe720815cab58db3efa8d1e5b71c58e8d1fdb6b21bfc66a9865f852c1b4b640e94bd908469e7151f9bbca3ce53224a27062ceb240a105bd3132dc18544477794c373bc0fb5a267885c857d4ccb4d31742b7a29624029fd05940de3f9f9b6e0a9a237672bc624ba2893a21709833c5276d413631bdde6ae7008c697a8ef428a79dbf6e8bbeb47c4e408ef656d9dc19b8b5d49bc091e2177357594c8acd41c101c7750cb11b5be6a194b8f877088c9828e3507dada17bb14bb2c738903c7aab40c545c46aa53823b120181a16ce92876288c4acd815b233d96bb572b162ec1b9d712f2c3966caac9cf174f3aedfec4d19ff9a87f8e21e8e1a9789b490ba05f1debd21732fb2e15a017c475c4fd00be042186dc29e68bb7ece192438f3b0c5ef8e4a53583a01943cf84bba5842173a6b3a7289566687c3018f764ab18103169919328713c3bd463d3398a1feb8e68e44cfe482f72847f46c80e6cc7f6ccf179f482c888594e76276653b48398a26c7c9e420cb6c1d3bc7646f33bb832bfba98489cadfbd55dd8b2c57687a47acba4ab390152d8fbb3f20327d824b284d288fb0152e49fc44678aed4d3f085b7c55de77bd45af812fc37944ad2454f99fbb34a583bf16b67659e6f216d34b1d79b1b4decc098a44207e1c5feeb6ce30acc2cf7e2b134490b442744772d184e59038aa517a97154181e4dfd94fe72a5a4ca2e7e22bce733d03e7d9319710befbc30d7826b728519ba74690e4f906587a0382895b90d82ed3e357faf8e59aca85fd2063ab592d83d245a919ea53c501b9accd2a1ed951f43c049ab9d25c7f1b70ae4f942edb1f311f7417833062245b429d4f013ae9019ff52044c97c73b8882cf03955c739f874a029637c0f0607100e3070f408d082aa7a2abf13e73bd1e252c228aba7a9c1f075bc439571b35932f5c912cb0b38da1c95e64fcf9bfec0b9b0dd8f042fdf05e5058299e96e4185074919d90b7b3b0a97e2242ca08cd99c9ecb12fc49adb2b257240cc387802f00e0e49952663ea278408709bce5b363c036093d7a05d440c9e7a7abb3d71ebb4d10bfc7781bcd66f79322c18262dfc2dccf3e5f1ea98bea3caae8a83706312764423a692ae0c1e2e23b016865ffb125b223857547ac7e2468433b5269843abbabbe9f6f438d7e387e3617a219f62540e7343e1bbf49355fb5a1938048439cba5cee819199b2b5c39fd351aa274536aadb682b578943f0ccf48e4ec7ddc938e2fd01acfaa1e7217f7b389285c0dfd31a1545ed3a85fac8eb9dab6ee826af90f9e1ee5d555dd1c05aec077f7c803cbc2f1cf98393f0f37838ffea372ff708886b05934e1a64512de144608864a88a5c3a173fdcfdf5725da916ed507e4caec8787befb91e3ec9b222fa09f374bd96881ac2ddd1f885d42ea584ce08b0e455a350ae54d76349aa68c71ae";

#[test]
fn test_handshake() {
    env_logger::init();

    let mut data = Vec::new();
    data.append(&mut hex::decode(SERVER_HELLO).unwrap());
    data.append(&mut hex::decode("140303000101").unwrap());
    data.append(&mut hex::decode(WRAPPER).unwrap());

    let io = MockInputOutput::new(data);
    let random = [0u8; 32];
    let mut key: [u8; 32] = [0u8; 32];
    hex::decode_to_slice(CLIENT_EPHEMERAL_PRIVATE, &mut key).unwrap();

    let mut tls = Session::new_test(io, "www.google.com", random, key);

    tls.client_hello = Some(Buffer::<8192>::new_from_slice(
        &hex::decode(CLIENT_HELLO).unwrap(),
    ));

    tls.test_process_server_hello().unwrap();

    println!("ClientHello {:02x?}", tls.client_hello.unwrap().slice());
    println!("ServerHello {:02x?}", tls.server_hello.unwrap().slice());
    println!(
        "client_handshake_key {:02x?}",
        tls.client_handshake_key.unwrap().slice()
    );

    assert!(
        tls.client_handshake_key.unwrap().slice()
            == &hex::decode("7154f314e6be7dc008df2c832baa1d39").unwrap()
    );
    assert!(
        tls.server_handshake_key.unwrap().slice()
            == &hex::decode("844780a7acad9f980fa25c114e43402a").unwrap()
    );
    assert!(
        tls.client_handshake_iv.unwrap().slice()
            == &hex::decode("71abc2cae4c699d47c600268").unwrap()
    );
    assert!(
        tls.server_handshake_iv.unwrap().slice()
            == &hex::decode("4c042ddc120a38d1417fc815").unwrap()
    );

    assert!(
        tls.client_application_key.unwrap().slice()
            == &hex::decode("49134b95328f279f0183860589ac6707").unwrap()
    );
    assert!(
        tls.client_application_iv.unwrap().slice()
            == &hex::decode("bc4dd5f7b98acff85466261d").unwrap()
    );
    assert!(
        tls.server_application_key.unwrap().slice()
            == &hex::decode("0b6d22c8ff68097ea871c672073773bf").unwrap()
    );
    assert!(
        tls.server_application_iv.unwrap().slice()
            == &hex::decode("1b13dd9f8d8f17091d34b349").unwrap()
    );

    assert_eq!(
        tls.generate_verify_data().slice(),
        &hex::decode("976017a77ae47f1658e28f7085fe37d149d1e9c91f56e1aebbe0c6bb054bd92b").unwrap()
    );

    assert_eq!(
        tls.encrypt_application_data(Buffer::new_from_slice(b"ping"))
            .slice(),
        &hex::decode("1703030015c74061535eb12f5f25a781957874742ab7fb305dd5").unwrap()
    );
}

struct MockInputOutput {
    server_data: Vec<u8>,
    index: usize,
}

impl MockInputOutput {
    fn new(server_data: Vec<u8>) -> MockInputOutput {
        MockInputOutput {
            server_data,
            index: 0,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
enum IoError {
    Other,
}

impl embedded_io::Error for IoError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl Io for MockInputOutput {
    type Error = IoError;
}

impl Read for MockInputOutput {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let len = usize::min(self.server_data.len() - self.index, buf.len());
        buf[..len].copy_from_slice(&self.server_data.as_slice()[self.index..][..len]);
        self.index += len;
        Ok(len)
    }
}

impl Write for MockInputOutput {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        // nothing
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
