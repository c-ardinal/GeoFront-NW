# Third-party notices

GeoFront-NW itself is MIT licensed (`LICENSE`, c-ardinal). It uses the software and data below. Versions are the ones
pinned in this repository (`compose.yaml`, the Dockerfiles, `testbed/requirements.txt`, `command-center/`). Licenses are
those the projects publish for these versions; check the upstream project when you update a version.

"YAMAHA", "RTX" and "WLX" are trademarks of Yamaha Corporation. They are used only to name the devices the drivers in
`drivers/yamaha-*` are written for; this project is not affiliated with or endorsed by Yamaha Corporation.

## Loaded by the browser at run time (not contained in this repository or its images)

| Component | Version | License | Source |
|---|---|---|---|
| globe.gl (includes three.js, three-globe) | 2.46.2 | MIT | https://github.com/vasturiano/globe.gl (cdn.jsdelivr.net, SRI pinned) |
| three-globe example textures (earth night, topology, night sky) | 2.45.6 | as published in the three-globe repository (MIT; imagery derived from NASA, public domain) | https://github.com/vasturiano/three-globe/tree/master/example/img |
| Natural Earth 110m countries (globe.gl example dataset, theme `film`) | 2.46.2 | public domain | https://www.naturalearthdata.com/ |
| Fonts from Google Fonts: IBM Plex Sans, IBM Plex Mono, Orbitron; theme `film`: Oswald, Shippori Mincho B1, Noto Serif JP | — | SIL Open Font License 1.1 | https://fonts.google.com/ (served by Google; no font file is bundled here) |

## Python packages inside the self-built images (`ghcr.io/c-ardinal/geofront-nw-*`)

| Package | Version | License | Image |
|---|---|---|---|
| CPython (base image python:3.12-slim, Debian) | 3.12 | PSF-2.0; Debian packages under their own licenses (`/usr/share/doc/*/copyright` in the image) | all |
| PyYAML | 6.0.3 | MIT | tools |
| argon2-cffi | 25.1.0 | MIT | tools |
| argon2-cffi-bindings | 26.1.0 | MIT (bundles the Argon2 reference implementation, CC0 / Apache-2.0) | tools |
| cffi | 2.1.1 | MIT | tools |
| pycparser | 3.12 | BSD-3-Clause | tools |
| maxminddb | 3.2.0 | Apache-2.0 | flowd |

Test fixture only (`testbed` image, never published): snmpsim 1.2.2, pysnmp 7.1.30, pysmi 2.0.0, pyasn1 0.6.4 (BSD-2-Clause);
cryptography 50.0.2 (Apache-2.0 or BSD-3-Clause); Jinja2 3.1.6, MarkupSafe 3.0.4, idna 3.20 (BSD-3-Clause); lark 1.3.1,
charset-normalizer 3.5.2, urllib3 2.8.0, cffi 2.1.1 (MIT); pycparser 3.12 (BSD-3-Clause); requests 2.34.2 (Apache-2.0);
certifi 2026.10.23 (MPL-2.0).

## GPL software inside the self-built images

| Component | Version | License | Image | Source code |
|---|---|---|---|---|
| tshark (Wireshark), Debian package `tshark` | 4.4.x | GPL-2.0-or-later | analyzer | Debian source package `wireshark` (`apt-get source wireshark`, https://sources.debian.org/src/wireshark/), upstream https://www.wireshark.org/download.html |
| dumpcap (Wireshark), Debian package `wireshark-common` | 4.4.x | GPL-2.0-or-later | capture | as above |

The images run these programs unmodified as separate processes. Whoever distributes the images (GHCR) must make the
corresponding source available: the exact Debian version is in the image (`dpkg -s tshark wireshark-common`), and its
source is the Debian source package of that version (snapshot.debian.org keeps every version).

## Container images used unmodified (pulled from their registries, pinned by digest)

| Image | License |
|---|---|
| caddy | Apache-2.0 |
| authelia/authelia | Apache-2.0 |
| nginx | BSD-2-Clause |
| prom/prometheus, prom/alertmanager, prom/snmp-exporter | Apache-2.0 |
| grafana/grafana, grafana/loki | AGPL-3.0 |
| grafana/alloy | Apache-2.0 |
| python (base of the self-built images) | PSF-2.0 + Debian |

## Data downloaded by the operator

| Data | License | Notes |
|---|---|---|
| DB-IP Lite: IP to City Lite, IP to ASN Lite (`tools geoip update`) | Creative Commons Attribution 4.0 (CC BY 4.0) | Not contained in the repository or the images. Attribution "IP Geolocation by DB-IP" (https://db-ip.com) is shown on the screens and in the README |
| Map tiles of the Grafana wallboard: Esri World Dark Gray Canvas | Esri terms of use | Fetched by the browser at run time |

## Synthetic data in this repository

`demo/demo-home.pcap` (made by `demo/make_demo_pcap.py`), the demo devices (`drivers/*/demo.json`) and the syslog
fixtures (`drivers/*/syslog.jsonl`) are synthetic and part of this project (MIT). They use documentation addresses
(RFC 5737 / RFC 3849), YAMAHA's factory default subnet 192.168.100.0/24 as an example, and locally administered MACs.
