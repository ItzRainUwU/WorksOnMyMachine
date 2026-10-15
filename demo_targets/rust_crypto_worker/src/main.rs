include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use openssl::sha::sha256;

fn main() {
    let digest = sha256(b"fixture payload");
    println!("crypto worker digest: {:02x?}", digest);
}
