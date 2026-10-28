VoltageGPU, Confidential VM, 8x H100 node in NVIDIA multi-GPU Protected PCIe mode
Captured on 10 September 2026 from inside a tenant VM (h100-xlarge), over SSH.
Article: https://voltagegpu.com/blog/two-proofs-tdx-nvidia-h200-attestation-tenant
Guide:   https://docs.voltagegpu.com/pods/confidential-vm#gpu-attestation

What this proves
----------------
NVIDIA's remote attestation service (NRAS v3) returned "Attestation Successful"
for all eight GPUs of the node, from evidence generated inside the VM with a
nonce the tenant chose. Per GPU: nonce match, report signature, certificate
chain, driver RIM and VBIOS RIM fetched with measurements available, measres
success, hwmodel GH100, secure boot on, debug disabled.

What it does not prove
----------------------
NVSwitch attestation. The SDK (nv-attestation-sdk 2.7.3) collected GPU evidence
only and NRAS answered INVALID_EVIDENCE on the switch endpoint. Until that
verifies, we say "GPU attestation verified, NVSwitch not yet".

How the state reads on a multi-GPU node
---------------------------------------
    CC State                   : OFF
    Multi-GPU Mode             : Protected PCIe
    CPU CC Capabilities        : INTEL TDX
    GPU CC Capabilities        : CC Capable
    CC GPUs Ready State        : Ready
"CC State OFF" is how Protected PCIe reports; the Multi-GPU Mode line is the
one to read. If Ready State reads Not Ready, run
"sudo nvidia-smi conf-compute -srs 1". The attestation SDK must be called with
get_evidence(options={"ppcie_mode": False}); the option means "standalone
mode" and defaults to True, which the SDK refuses on a PPCIe system.

Files
-----
nras_token.json       17,522 bytes. JSON array: element 0 is the SDK's overall
                      JWT, element 1 holds REMOTE_GPU_CLAIMS with one NVIDIA-
                      signed JWT per GPU (GPU-0 to GPU-7), iss
                      https://nras.attestation.nvidia.com, eat_nonce
                      211b20f54486162c3a447c8a88e4a6f9f6416e4c0b10d96e59d9f7fefad1c99d.
node-state.txt        nvidia-smi conf-compute -q, per-GPU driver/VBIOS/bus id,
                      NVLink topology, CPU model, /dev/tdx_guest.
attestation-run.txt   Console output of the run, both attempts (GPU + switch,
                      then GPU only).

Host: [redacted], 8x NVIDIA H100 80GB HBM3, driver 595.71.05, VBIOS
96.00.CF.00.01, 96 vCPU, 1.3 TB RAM. The VM was deleted after the capture.

nvswitch-diag.txt     Second VM on the same host, 10 September 2026: lspci (8 GPUs
                      plus 4 NVSwitch [10de:22a3]), device nodes, fabric manager,
                      and the NVSwitch evidence collection failing in the guest
                      with "undefined symbol: nscq_session_create" (no
                      libnvidia-nscq in the image), hence NRAS INVALID_EVIDENCE
                      on the switch endpoint. GPU attestation succeeded again.

27 October 2026: the host's IP address is masked in README.txt, node-state.txt
(first line, the SSH warning) and nvswitch-diag.txt (first line). Nothing else
in these files changed; nras_token.json is untouched.
