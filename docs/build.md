# Linux builds

Native development:

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Portable server/client: install the Rust musl target in your chosen toolchain,
then run `scripts/build-portable.sh`. It selects x86_64 or aarch64 musl. An
explicit supported target works too. `READB_CARGO` can select an isolated Cargo;
standard `RUSTC` and `CARGO_TARGET_DIR` keep that toolchain/cache separate.
This script never downloads tools or accepts SDK terms.

Verify the resulting ELF and run the account/privilege and filesystem tests on
the destination host. Build success alone is insufficient. aarch64 acceptance
is still pending. Android JNI uses its own Android target/build instructions.

Static glibc is rejected. A real Arch-to-Ubuntu test aborted when group lookup
loaded the destination's NSS module into the static runtime. musl passes the
root-to-user transition on Blackwall. Native dynamic GNU builds remain available
for a host's own libc/NSS. musl account lookup uses local passwd/group files;
directory-managed accounts need a verified native build, not silent assumptions.

The kernel `renameat2` syscall supplies atomic no-replace publication even where
the bundled musl CRT has no wrapper. Missing kernel support is an error; there
is no unsafe replace fallback.

Runtime linking: [Rust Reference](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes).
