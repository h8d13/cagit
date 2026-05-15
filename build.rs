fn main() {
    cc::Build::new()
        .file("csrc/wrapper.c")
        .include("csrc")
        .opt_level(3)
        .flag_if_supported("-mavx2")
        .flag_if_supported("-msse2")
        .flag_if_supported("-maes")
        .compile("premhash");

    println!("cargo:rerun-if-changed=csrc/wrapper.c");
    println!("cargo:rerun-if-changed=csrc/hash_table8.h");
}
