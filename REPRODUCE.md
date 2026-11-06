# Reproduction and historical recipe

Host checks require Python 3.11+ only:

```sh
python3 -m unittest discover -s tools -v
python3 tools/btf_graph_audit.py BASE.btf CANDIDATE.btf --output report.json
python3 tools/verify_btf_ids.py VMLINUX --output ids.json
python3 tools/check_module_crc.py --symvers Module.symvers MODULE.ko
```

Inputs must be independently acquired and authorized. Never pass personal artifacts to public CI. ELF parser targets ELF64 little-endian AArch64. Use Module.symvers from the exact matching kernel, not a similarly named release. The ELF library exports() helper assumes section-relative symbols in relocatable objects; do not use it blindly on linked vmlinux virtual addresses.

Historical BTF-preserving construction: Nothing Phone (3) A024/Metroid, Nothing OS B4.1-260814-1733 (Android16); kernel/common 1a9b880d342bb9dcfa59abf8a26af3b970009f8b, clang18 r510928, pahole1.25/dwarves82a6e19c8e8a4f0c6fe065e8d4b0f67ee122551b, libbpf45dc3752d2bdd3de48b53feca441f6a872d15eb1. The patch adds a KSU compilation-unit exclusion before pahole BTF encoding at the pinned Kleaf DWARF prefix. Check applicability with `git apply --check patches/btf-cu-filter.patch` in the matching kernel checkout. The prefix is a build-system path, not a private host path.

Initial patch recipe used KernelSU-Next3.4.0 (1a879d6a866f80b1fa1c1009a2ffa747873cbb5e). A later, separate historical qualification used3.4.2 (4c706b5938665866ebe16944a481a7b91e3396af), UAPI5/code33355 and SUSFS2.3.0 integration based on a0f9c59e2243f8a5db955f4ad1686d5e0ad26e1a. A later SUSFS head bd7d199ac87808001127e8a6d076832e2938cf0d is a distinct revision, not the tested integration.

This export does not recreate the full OEM build tree/configuration or bundle OEM modules. It supplies the adaptation and validation protocol; complete kernel build reproducibility remains NOT_QUALIFIED without a separately pinned OEM source/config/module set. Required gates: exact config and release, exports/CRC equality, byte-identical OEM base BTF, resolved BTF ID validation, matching split-module BTF interpretation and comparison against OEM parser failures. Static gates precede any separately authorized RAM boot and persistent-install qualification. No flash command or image is provided.
