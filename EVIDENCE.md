# Evidence

Historical B4.1-260814-1733 observations, not Nothing OS5 qualification:

- Static KSU3.4.2/SUSFS2.3.0 report:9,150 exports/CRC;525 unique OEM ELF files/747 occurrences;541 resolved IDs,31 sets and95 standalone IDs; OEM base BTF equality reported. OEM-baseline libbpf rejections persisted; not all modules passed parsing.
- RAM boot on2026-10-14: root/SUSFS interface and SELinux Enforcing observed for approximately7min44s. An init SIGABRT occurred in one observation. Camera/sensor enumeration is not physical testing.
- Persistent installation on2026-10-15: two cycles observed. Not long-term stability. Reported locked/green properties were spoofed; fastboot historically showed unlocked.
- TMPFS_XATTR variant: six additional types (141581→141587),21094 base IDs moved and13281 local references in96 modules shifted because the split-BTF local start ID depends on base type count. Earlier claims that53 modules were wholly unaffected were superseded. Merely reordering IDs is insufficient; an OEM-count-preserving solution was not proven.

These rewritten summaries omit personal logs and hashes. Export fixture tests and patch application are separate, in VALIDATION.md. No new hardware, boot, flash, root or production-network action occurred.
