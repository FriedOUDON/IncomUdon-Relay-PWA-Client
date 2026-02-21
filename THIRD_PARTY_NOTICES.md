# Third-Party Notices (pwa_client)

This `pwa_client/` package is distributed under the MIT License.
Third-party components keep their own licenses.

## 1) Opus (`libopus.so`)

- Upstream project: https://opus-codec.org/
- License text path: `LICENSES/opus/COPYING`
- Patent notice path: `LICENSES/opus/PATENT-NOTICE.txt`

When distributing binaries that include `libopus.so`, keep the above copyright
notice, license conditions, and disclaimer in your distribution materials.

## 2) libcodec2 (voice codec, user-provided dynamic library policy)

- Project policy for public releases: libcodec2 binaries are not bundled by
  default. Users may install/provide libcodec2 dynamic libraries separately.
- License: GNU LGPL v2.1.
- License text copy in this repo: `LICENSES/LGPL-2.1.txt`.
- Source used for custom builds:
  - https://github.com/FriedOUDON/libcodec2
- Original upstream project:
  - https://github.com/drowe67/codec2
- License reference:
  - https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html
