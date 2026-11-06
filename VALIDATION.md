# Export validation — 2026-11-06

12 synthetic Python3.13.5 tests PASS (six BTF graph cases, six CRC/parser cases). Patch apply --check PASS against scripts/link-vmlinux.sh fetched from pinned AOSP kernel/common; file mode warning reflects the HTTP copy, not a patch mismatch.

No complete kernel build, real ELF/module qualification, hardware boot or flash: NOT_RUN. New CRC cases test comparison/parser primitives, not a fabricated OEM load test. The portable BTF CLI replaces private log/dependency traversal. Independent review informed selection and limitations; source reports remain private.
