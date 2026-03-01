# libcodec2 bundle directory

Place user-provided `libcodec2.so` files here when you want to bundle them with
this `pwa_client` package.

Recommended layout:

- `third_party/libcodec2/linux-x86_64/libcodec2.so`
- `third_party/libcodec2/linux-musl-x86_64/libcodec2.so`
- `third_party/libcodec2/linux-raspi-armv7l/libcodec2.so`
- `third_party/libcodec2/linux-raspi-aarch64/libcodec2.so`
- `third_party/libcodec2/linux-musl-armv7l/libcodec2.so`
- `third_party/libcodec2/linux-musl-aarch64/libcodec2.so`

Auto-search (when `-codec2-lib` is not specified) checks these bundle directories
under `/opt/libcodec2`, `/opt/codec2`, and `third_party/libcodec2`.

This repository does not include `libcodec2.so` by default.

Compatibility requirement for recent IncomUdon builds:

- `libcodec2.so` must provide `incomudon_codec2_abi_version()`.
- Expected ABI value is `2026022801`.
