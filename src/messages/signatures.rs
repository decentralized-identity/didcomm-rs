pub struct Signature {
    header: SignatureHeader,
    signature: Vec<u8>,
}

pub struct SignatureHeader {
    algorythm: String,
    key_id: String,
}