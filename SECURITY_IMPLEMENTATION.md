# Boot and Network Integrity Coverage

## Implemented

- Explicit EFI System Partition discovery using the GPT ESP partition GUID.
- Raw protective MBR inspection.
- Primary and backup GPT header bounds and CRC32 validation.
- Primary and backup GPT partition-array CRC32 validation.
- Comparison of reciprocal GPT LBAs, disk GUID and partition-array CRC.
- EFI executable discovery, trust validation, SHA-256 and protected baseline.
- Machine-scoped DPAPI baseline stored in ProgramData.
- BCD registry-hive header and Objects-key validation.
- UEFI BootOrder, BootNext, network-boot and Secure Boot inventory.
- TCG 1.2 and TCG2 Measured Boot log structural parsing.
- Active WFP filter, callout, provider, sublayer and service correlation.
- SetupAPI NetService/NDIS driver inventory.
- Repeatable 256 KiB TCP loopback integrity test.
- Evidence rule ID, source, confidence and state in scan reports.
- Administrator manifest for raw disk, ESP and firmware-variable access.

## False-positive policy

- Secure Boot disabled is configuration evidence, not a cheat verdict.
- PXE, HTTP Boot and unclassified dual-boot entries are review items.
- A JMP or trampoline at an EFI entry point is not proof of a hook.
- Trusted third-party WFP/NDIS drivers are inventory-only findings.
- Microsoft pinning is not applied to the generic `bootx64.efi` fallback path.
- A PE checksum mismatch is not treated as tampering when Authenticode trust succeeds.
- A signed EFI baseline change is review-level; an unsigned change is suspicious.
- Raw-disk access failures and unavailable TPM logs never produce a clean verdict.
- TCP truncation requires at least two established, fully-sent attempts with altered
  or incomplete received content.

## Confidence boundary

The online scanner cannot prove the absence of a kernel or firmware rootkit. A
component already controlling the running kernel can falsify user-mode API results.
Confirmed remediation-grade bootkit analysis still requires one of:

- an independently signed kernel collection driver;
- a WinRE/offline build reading the target disk while the installed OS is stopped;
- remote attestation comparing TPM quotes and PCR reconstruction against a trusted
  verifier.

Those components require a driver-signing certificate, deployment policy and, for
remote attestation, a verifier service. The current executable reports unavailable
or inconclusive coverage instead of claiming those guarantees.
