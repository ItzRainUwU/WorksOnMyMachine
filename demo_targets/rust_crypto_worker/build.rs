fn main() {
    println!("cargo:rerun-if-changed=native/crypto.h");

    let bindings = bindgen::Builder::default()
        .header("native/crypto.h")
        .generate()
        .expect("unable to generate crypto bindings");

    bindings
        .write_to_file(std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("could not write bindings");
}
