# libopus bundle directory

Place user-provided `libopus.so` files here when you want to bundle them with
this `pwa_client` package.

Recommended layout:

- `third_party/libopus/linux-x86_64/libopus.so`
- `third_party/libopus/linux-musl-x86_64/libopus.so`
- `third_party/libopus/linux-raspi-armv7l/libopus.so`
- `third_party/libopus/linux-raspi-aarch64/libopus.so`
- `third_party/libopus/linux-musl-armv7l/libopus.so`
- `third_party/libopus/linux-musl-aarch64/libopus.so`

Auto-search (when `-opus-lib` is not specified) checks these bundle directories
under `/opt/libopus` and `third_party/libopus`.

This repository does not include `libopus.so` by default.

When redistributing, include the notices in:
- `LICENSES/opus/COPYING`
- `LICENSES/opus/PATENT-NOTICE.txt`
