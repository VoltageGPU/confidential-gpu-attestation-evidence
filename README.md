# Confidential GPU attestation evidence

Real, dated attestation bundles captured **by the tenant, from inside** Intel TDX Confidential VMs
with NVIDIA GPUs in confidential compute mode, on nonces the tenant chose. Every bundle here can be
re-verified on your own machine, offline, with an open-source verifier. None of it is produced
server-side by the provider.

This repository is the raw material behind https://voltagegpu.com/api/attestation/evidence. It exists
so that anyone can check the claims rather than take them on trust, and so that the *limits* we found
are as public as the successes.

## What is here

| Folder | Hardware | Date | Result | Notes |
|---|---|---|---|---|
| `h200-single-2026-09-04/` | 1x H200, TDX VM | 4 Sept 2026 | Intel TDX quote + NVIDIA NRAS token, CC State ON | The original "two proofs" run: `quote.bin` (5,243 B), `gpu_report.bin` (4,129 B), `nras_token.json`, `nonce.txt`, `report_data.bin` |
| `ppcie-8x-h100-2026-09-10/` | 8x H100, TDX VM, NVIDIA Protected PCIe mode | 10 Sept 2026 | NRAS successful for all 8 GPUs | `nvidia-smi` reads CC State OFF next to Multi-GPU Mode Protected PCIe, which is the normal reading for that mode; `nvswitch-diag.txt` documents the fabric |
| `voltage-verify-8xh100-2026-09-12/` | 8x H100, TDX VM | 12 Sept 2026 | `voltage-verify` bundle, RESULT: VERIFIED | Manifest-bound: TDX `report_data` = SHA-512(manifest), NRAS nonce = SHA-256(manifest). Replay with the commands below |
| `nvswitch-2026-09-16/` | 8x H100 node | 16 Sept 2026 | **Not attestable from inside the guest** | With NVIDIA `nvattest` 1.2.0 and `libnvidia-nscq`, the NSCQ session would not open from a TDX guest (`NSCQ_RC_WARNING: RDT init failure`). Re-tested on 19 Sept 2026 with `libnvidia-nscq` taken without a branch suffix and pinned to the driver version: the session now opens and switch evidence is collected, but certificate chain validation fails because `ocsp.ndis.nvidia.com` is unreachable over TLS from the guest (`SSL connect error 35`). On 27 Oct 2026 that error was traced to TCP connections reset on the network path, not to the tool (see `nvattest-2.0.0-single-gpu-2026-10-27/`). The NVLink fabric stays unverified and is not claimed. Published as a limit, not hidden |
| `rtx6000b-2026-09-17/` | 1x RTX PRO 6000 Blackwell (96 GB), TDX VM | 17 Sept 2026 | `voltage-verify` bundle, RESULT: VERIFIED, CC State ON | Quote v4 chained to the Intel root, NRAS tokens on the manifest nonce |
| `rtx6000b-api-2026-09-17/` | 1x RTX PRO 6000 Blackwell, TDX VM | 17 Sept 2026 | RESULT: VERIFIED, produced with **an API key alone**, no dashboard | The run that found two gaps in the provider's API (documented at the link below), then re-run after the fixes. Whole run cost 0.60 USD |
| `nvattest-2.0.0-single-gpu-2026-10-27/` | 1x H100, TDX VM, CC State ON | 27 Oct 2026 | **Correction of 19 Sept**: `SSL connect error (35)` reproduced with one GPU, nvattest 1.2.0 and 2.0.0; the cause is TCP resets on the network path, not the tool | nvattest 2.0.0 reports `Connection reset by peer (35)`; system curl fails at a similar rate on the same OCSP and RIM addresses; failing connections carry a SYN-ACK with MSS 0, some are reset by a TTL 63 packet; remote verification (NRAS) passes. strace, ldd/readelf, anonymised pcaps and scripts included. The 19 Sept conclusion in `nscq-retest-2026-09-19-21h12/` is withdrawn |

Not in this repository, because it never happened: 8x H200, B200 and B300 have never been available to
test, and are listed as *not attested* at https://voltagegpu.com/api/attestation/evidence.

## Re-verify a bundle yourself

```bash
pip install voltage-verify            # MIT, https://github.com/VoltageGPU/voltage-verify

# RTX PRO 6000, 17 Sept 2026 (challenge is printed in the folder's manifest.json)
cd rtx6000b-2026-09-17
voltage-verify verify bundle.json \
  --challenge "$(python3 -c 'import json;print(json.load(open("manifest.json"))["challenge"])')" \
  --hwmodel GB20X --gpus 1
voltage-verify verify bundle.json --offline --challenge "<same challenge>"   # no network at all
voltage-verify selftest bundle.json --challenge "<same challenge>"           # six mutations rejected

# 8x H100, 12 Sept 2026
cd ../voltage-verify-8xh100-2026-09-12
voltage-verify verify bundle-8xh100-2026-09-12.json \
  --challenge ef7f54c160627ee536a02b5e73896ac4b1ac2cdefdb7cfaaf2366a7d33cc8731 --hwmodel GH100 --gpus 8
```

Expected on every bundle: `RESULT: VERIFIED`, platform TCB `UpToDate`, Quoting Enclave `UpToDate`,
NVIDIA `measres success` per GPU. A wrong `--challenge` must give `NOT VERIFIED (manifest.challenge)`:
that is the replay protection working.

The `h200-single-2026-09-04/` and `ppcie-8x-h100-2026-09-10/` folders predate the tool and hold the
raw artifacts (quote, GPU report, NRAS token, nonce) with SHA-256 sums; their `README.txt` explains
what each file is and how the nonce binds them.

## Produce your own

`two-proofs-in-the-vm.sh` is the script that generates a folder like these from inside any TDX VM
with a confidential NVIDIA GPU (it reads the kernel's configfs TSM interface and calls NVIDIA's own
SDK, nothing provider-specific). Run it over SSH, copy `/tmp/proofs.tgz` out, verify on your machine.

## What this proves, and what it does not

Verified means: a genuine Intel TDX Trust Domain on a platform whose certificate chains to Intel's
root, at an acceptable TCB, and NVIDIA's service signing that the GPU passed attestation with secure
boot on and debug off, both bound to a value the tenant chose after issuing it.

Verified does **not** mean the GPU executed a particular model, nor anything about the host's memory
integrity mode (logical vs cryptographic), which is not readable from inside a guest. After DDRop
(September 2026) that distinction matters; see `tdx-guest-probe` for what a guest can and cannot see:
https://github.com/VoltageGPU/tdx-guest-probe

## Links

- Public index of attested SKUs (JSON, no account): https://voltagegpu.com/api/attestation/evidence
- The article with the original outputs: https://voltagegpu.com/blog/two-proofs-tdx-nvidia-h200-attestation-tenant
- The API-only run, and the two gaps it found: https://voltagegpu.com/blog/confidential-gpu-from-the-api-alone-deploy-attest-verify
- Verifier source: https://github.com/VoltageGPU/voltage-verify

## License

Evidence files (bundles, quotes, tokens, logs): CC BY 4.0. Scripts: MIT. Copyright 2026 VOLTAGE EI.
