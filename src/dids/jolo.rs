/// did::jolo parser for DIDComm purposes.
/// [Spec](https://github.com/jolocom/jolo-did-method/blob/master/packages/jolocom-did-method-specification.md)
///
#[derive(Serialize, Deserialize)]
pub struct Jolo {
    context: String,
    id: String,
    authentication: Authentication,
    service: Vec<Service>,
}

impl Jolo {
    pub fn new() -> Self {
        Jolo{
            context: String::default(),
            id: String::default(),
            authentication: Authentication::new(),
            service: vec!(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Authentication {
    id: String,
    type_: String,
    controller: String,
    public_key: PK,   
}

impl Authentication {
    pub fn new() -> Self {
        Authentication {
            id: String::default(),
            type_: String::default(),
            controller: String::default(),
            public_key: PK::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PK {
    algorythm: String,
    value: String,
}

impl PK {
    pub fn new() -> Self {
        PK {
            algorythm: String::default(),
            value: String::default(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Service {
    id: String,
    type_: String,
    service_endpoint: String,
}
