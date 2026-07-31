/**
 * build script for adding a workaround to fix builds on NDK >= 23
 *
 * here's the related bug-report to cargo-ndk (they won't fix it)
 * https://github.com/bbqsrc/cargo-ndk/issues/94
 *
 * also see:
 * https://doc.rust-lang.org/cargo/reference/build-scripts.html
 *
 * NOTE: clang path needs to be updated whenever we upgrade clang
 */
fn main() {
    let target = std::env::var("TARGET").unwrap();

    if target == "i686-linux-android" {
        let ndk_home = std::env::var("NDK_HOME").unwrap();
        println!("cargo:rustc-link-lib=static=clang_rt.builtins-i686-android");
        println!("cargo:rustc-link-search={}/toolchains/llvm/prebuilt/linux-x86_64/lib/clang/17/lib/linux", ndk_home);
    }

    if target == "x86_64-linux-android" {
        let ndk_home = std::env::var("NDK_HOME").unwrap();
        println!("cargo:rustc-link-lib=static=clang_rt.builtins-x86_64-android");
        println!("cargo:rustc-link-search={}/toolchains/llvm/prebuilt/linux-x86_64/lib/clang/17/lib/linux", ndk_home);
    }
}
