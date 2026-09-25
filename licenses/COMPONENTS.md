# Third-party components in v2026.09.26.4

The installer does not replace the independent Xray, WDTT or CSQTT installation.
Only amd64 release artifacts are mirrored. See `components.json` for exact hashes.

| Component | Pinned source/version | License material |
|---|---|---|
| Snell server | 5.0.1, https://dl.nssurge.com/snell/snell-server-v5.0.1-linux-amd64.zip | Unmodified upstream binary; upstream does not provide source in this archive. https://kb.nssurge.com/surge-knowledge-base/release-notes/snell |
| Mieru / mita | https://github.com/enfein/mieru/tree/v3.38.0 | `mieru.txt`, `mita.txt`; complete upstream source in `mita-source.tar.gz` release asset |
| OpenFlux | https://github.com/p1neappleXpress/OpenFlux/tree/d13aa5b701c8ee5311aa638de16c70ea094d9dfd | `openflux.txt`; corresponding source, including this repository's Multi-stream/Boards patch, in `openflux-source.tar.gz` |
| WebDAV Tunnel | https://github.com/spkprsnts/webdav-tunnel/tree/b1af4c05eb80fd29a6f676be894fa61cd12a3dec | `webdav-tunnel.txt`; source in `webdav-tunnel-source.tar.gz` |
| CottenDNS | https://github.com/WhiteDNS/CottenDNS/releases/tag/v2026.09.01.221444-530ffbf | `cottendns.txt`; upstream binary archive retained unchanged |
| MasterDnsVPN | https://github.com/masterking32/MasterDnsVPN/releases/tag/v2026.06.13.234407-7de2476 | `masterdns.txt`; upstream binary archive retained unchanged |

Go source archives retain `go.mod` and `go.sum`, including pinned dependencies.
OpenFlux's archive already contains `patches/openflux-multistream.patch` applied;
do not apply it a second time. Build OpenFlux and WebDAV from their source roots
with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' .`.
Use each source archive's documented build procedure and Go toolchain version.
The main installer uses prebuilt, checked assets and never fetches Go modules.
