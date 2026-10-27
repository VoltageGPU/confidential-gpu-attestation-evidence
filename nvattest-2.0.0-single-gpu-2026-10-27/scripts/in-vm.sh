#!/usr/bin/env bash
# nvtrust#153 capture on a single-GPU confidential VM, 2026-10-27.
# Run as the image's default user:  bash /tmp/in-vm.sh </dev/null
# Raw outputs go to /tmp/cap153, packed into /tmp/cap153.tgz at the end.
# Needs /tmp/parse_tls.py (uploaded next to this script).
set -u
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
OUT=/tmp/cap153
rm -rf "$OUT" /tmp/cap153.tgz
mkdir -p "$OUT" && cd "$OUT" || exit 1
HOSTS="ocsp.ndis.nvidia.com rim.attestation.nvidia.com nras.attestation.nvidia.com"
NV_TIMEOUT=150
# Hard limit for the whole script: nvattest runs are skipped after 14 minutes.
DEADLINE=$(( $(date +%s) + 14 * 60 ))
APT="sudo -n apt-get -o DPkg::Lock::Timeout=240 -y -qq"
say() { echo; echo "===== $(date -u +%H:%M:%S) $* ====="; }
late() { [ "$(date +%s)" -ge "$DEADLINE" ]; }

say "0. sudo"
if ! sudo -n true 2>/dev/null; then echo "sudo asks for a password: stopping"; exit 2; fi
echo "passwordless sudo OK"
# This guest's own addresses, kept apart only to redact them from the outputs.
{ hostname -I; ip -o addr show scope global | awk '{print $4}'; } > "$OUT/.guest-addresses" 2>/dev/null

say "1. environment"
{
  echo "date_utc:  $(date -u +%FT%TZ)"
  echo "kernel:    $(uname -r)"
  echo "os:        $(. /etc/os-release; echo "$PRETTY_NAME")"
  echo "cloud image build: $(grep -hE '^(build_name|serial)' /etc/cloud/build.info 2>/dev/null | tr '\n' ' ')"
  echo "virt:      $(systemd-detect-virt 2>&1)"
  echo "tdx_guest: $(ls -l /dev/tdx_guest 2>&1)"
  sudo -n dmesg 2>/dev/null | grep -i 'tdx' | head -5
  echo "--- nvidia-smi"
  nvidia-smi --version 2>&1
  nvidia-smi --query-gpu=name,driver_version,vbios_version,memory.total --format=csv,noheader 2>&1
  nvidia-smi conf-compute -q 2>&1 | grep -E 'CC State|Multi-GPU Mode|CPU CC|GPU CC|Ready State'
  echo "--- packages"
  dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null \
    | grep -E '^(nvattest|libnvat|libcurl4|libcurl3|libssl3|openssl |ca-certificates|curl |libxmlsec1|libxml2 |cuda-keyring|libnvidia-compute|nvidia-driver|nvidia-kernel|linux-image)'
  echo "--- system TLS stack"
  openssl version -a 2>&1 | grep -E '^(OpenSSL|OPENSSLDIR|built on)'
  curl --version 2>&1 | head -1
  ls -l /etc/ssl/certs/ca-certificates.crt 2>&1
  echo "--- proxy and TLS-related environment"
  env | grep -iE '^(https?_proxy|no_proxy|all_proxy|ssl_cert_(file|dir)|curl_ca_bundle|openssl_conf|nvat_)=' || echo "user: none set"
  sudo -n env | grep -iE '^(https?_proxy|no_proxy|all_proxy|ssl_cert_(file|dir)|curl_ca_bundle|openssl_conf|nvat_)=' || echo "root: none set"
  grep -isE 'proxy' /etc/environment /etc/apt/apt.conf /etc/apt/apt.conf.d/* 2>/dev/null || echo "no proxy in /etc/environment or apt configuration"
  echo "IPv6 default routes: $(ip -6 route show default 2>/dev/null | wc -l)"
} > 00-environment.txt 2>&1
cat 00-environment.txt

say "2. system curl -v (user and root)"
{
  for h in $HOSTS; do
    echo "--- $h"
    echo "resolves to: $(getent ahosts "$h" | awk '{print $1}' | sort -u | tr '\n' ' ')"
    curl -v -s -o /dev/null -m 20 -w "RESULT user: http=%{http_code} ip=%{remote_ip} verify=%{ssl_verify_result} connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s\n" "https://$h/" 2>&1
    sudo -n curl -s -o /dev/null -m 20 -w "RESULT root: http=%{http_code} ip=%{remote_ip} verify=%{ssl_verify_result} connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s\n" "https://$h/" 2>&1
  done
  echo "--- ocsp.ndis.nvidia.com over plain HTTP"
  curl -s -o /dev/null -m 20 -w "RESULT http80: http=%{http_code} ip=%{remote_ip} total=%{time_total}s\n" "http://ocsp.ndis.nvidia.com/" 2>&1
} > 01-curl-verbose.txt 2>&1
grep -E '^(---|resolves|RESULT|\* SSL connection|\*  CAfile)' 01-curl-verbose.txt

say "3. openssl s_client"
{
  for h in $HOSTS; do
    echo "--- $h"
    echo | timeout 20 openssl s_client -connect "$h:443" -servername "$h" -brief 2>&1 | grep -vE '^(depth=|verify return:)'
    echo | timeout 20 openssl s_client -connect "$h:443" -servername "$h" -showcerts 2>/dev/null | grep -E '^ *[0-9]+ s:|^ +i:|^ +v:'
  done
} > 02-openssl-s_client.txt 2>&1
cat 02-openssl-s_client.txt

say "3b. hand-built ClientHello, small (x25519) vs large (X25519MLKEM768 + x25519)"
timeout 90 python3 /tmp/hello_probe.py $HOSTS > 02b-clienthello-size-probe.txt 2>&1
cat 02b-clienthello-size-probe.txt

say "4. apt: NVIDIA network repository, strace, binutils, tcpdump"
. /etc/os-release
DIST="ubuntu${VERSION_ID//./}"
{
  wget -q "https://developer.download.nvidia.com/compute/cuda/repos/$DIST/x86_64/cuda-keyring_1.1-1_all.deb" -O /tmp/cuda-keyring.deb \
    && sudo -n dpkg -i /tmp/cuda-keyring.deb
  $APT update
  $APT install strace binutils tcpdump
  echo "--- available versions"
  apt-cache madison nvattest libnvat
} > 03-apt.txt 2>&1
tail -n 25 03-apt.txt
command -v strace nm readelf tcpdump

BASELINE_ORIGIN="shipped with the image"
if ! command -v nvattest >/dev/null 2>&1; then
  V12=$(apt-cache madison nvattest | awk '$3 ~ /^1\.2\.0/ {print $3; exit}')
  BASELINE_ORIGIN="not on the image: installed $V12 from the NVIDIA repository"
  $APT install "nvattest=$V12" "libnvat=$V12" > 03b-apt-nvattest-baseline.txt 2>&1
fi
echo "baseline nvattest: $BASELINE_ORIGIN"

linkage() {  # $1 = output file
  local bin lib
  bin=$(readlink -f "$(command -v nvattest)")
  lib=$(ldd "$bin" | awk '/libnvat/ {print $3; exit}')
  {
    echo "origin: $2"
    echo "packages: $(dpkg-query -W -f='${Package} ${Version}  ' nvattest libnvat 2>/dev/null)"
    echo "nvattest version:"; nvattest version 2>&1 | head -5
    echo "--- ldd $bin"; ldd "$bin"
    if [ -n "$lib" ]; then
      echo "--- ldd $lib"; ldd "$lib"
      echo "--- NEEDED entries of $lib"; readelf -d "$lib" | grep NEEDED
      echo "--- TLS/HTTP stack strings embedded in $lib"
      strings -a "$lib" | grep -E '^(libcurl/[0-9]|OpenSSL [0-9]+\.[0-9]+\.[0-9]+|curl/[0-9])' | sort -u | head -10
      strings -a "$lib" | grep -E '^(OPENSSLDIR|ENGINESDIR|MODULESDIR):' | head -5
      echo "--- dynamic symbols defined by $lib"
      echo "OpenSSL-like (SSL_*, OPENSSL_*, EVP_*, X509_*): $(nm -D --defined-only "$lib" 2>/dev/null | awk '{print $3}' | grep -cE '^(SSL_|OPENSSL_|EVP_|X509_)')"
      echo "libcurl-like (curl_*): $(nm -D --defined-only "$lib" 2>/dev/null | awk '{print $3}' | grep -cE '^curl_')"
    fi
    echo "--- absolute CA paths compiled into the binary and library"
    strings -a "$bin" ${lib:+"$lib"} | grep -E '^/etc/(ssl|pki)|ca-certificates\.crt|ca-bundle\.crt|cacert\.pem' | sort -u | head -10
  } > "$1" 2>&1
}

nvrun() {  # $1 = output file, rest = nvattest arguments (run as root)
  local f="$1" t0 rc
  shift
  if late; then echo "--- $f skipped: time limit reached"; return; fi
  echo "\$ sudo nvattest $*" > "$f"
  t0=$(date +%s%N)
  sudo -n timeout "$NV_TIMEOUT" nvattest "$@" >> "$f" 2>&1
  rc=$?
  echo "exit=$rc elapsed_ms=$(( ($(date +%s%N) - t0) / 1000000 ))" >> "$f"
  echo "--- $f"
  grep -E 'rror|libcurl|SSL|TLS|OCSP|successful|failed|exit=' "$f" | tail -n 30
}

IFACE=$(ip route show default | awk '{print $5; exit}')
cap_start() { sudo -n tcpdump -Z root -i "$IFACE" -s 0 -U -w "$1" 'tcp port 443 or tcp port 80' >/dev/null 2>&1 & CAP_PID=$!; sleep 2; }
cap_stop() { sleep 1; sudo -n kill "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null; }

traced() {  # $1 = trace file, $2 = run output file, rest = nvattest arguments
  local tr="$1" f="$2" rc
  shift 2
  if late; then echo "--- $tr skipped: time limit reached"; return; fi
  echo "\$ sudo strace -f -tt -s 128 -e trace=network,openat -o $tr nvattest $*" > "$f"
  sudo -n timeout "$NV_TIMEOUT" strace -f -tt -s 128 -e trace=network,openat -o "$tr" nvattest "$@" >> "$f" 2>&1
  rc=$?
  echo "exit=$rc" >> "$f"
  sudo -n chmod 644 "$tr"
  echo "--- $tr ($(wc -l < "$tr") lines), run exit=$rc"
  echo "connect() calls:"; grep -E 'connect\(' "$tr" | grep -oE 'sin6?_addr=inet_(addr|pton)\([^)]*\)|sun_path="[^"]*"' | sort | uniq -c
  echo "CA / certificate files opened:"; grep -E 'openat\(' "$tr" | grep -iE 'cert|\.pem|\.crt|ca-bundle|openssl\.cnf|ssl/' | grep -oE '"[^"]+"[^)]*\) = [-0-9]+( [A-Z]+)?' | sort | uniq -c | head -25
}

say "5. baseline nvattest ($BASELINE_ORIGIN)"
linkage 10-baseline-linkage.txt "$BASELINE_ORIGIN"
cat 10-baseline-linkage.txt
cap_start 11-curl-reference.pcap
curl -s -o /dev/null -m 20 https://ocsp.ndis.nvidia.com/
cap_stop
cap_start 12-baseline.pcap
nvrun 12-baseline-gpu-local.txt attest --device gpu --verifier local --log-level debug
cap_stop
traced 13-baseline-strace.txt 13-baseline-strace-run.txt attest --device gpu --verifier local --log-level debug
nvrun 14-baseline-gpu-local-ocsp-http.txt attest --device gpu --verifier local --log-level debug --ocsp-url http://ocsp.ndis.nvidia.com

say "6. install nvattest 2.0.0 from the NVIDIA repository"
V20=$(apt-cache madison nvattest | awk '$3 ~ /^2\.0\.0/ {print $3; exit}')
echo "target version: $V20"
$APT install "nvattest=$V20" "libnvat=$V20" > 20-apt-nvattest-2.0.0.txt 2>&1
tail -n 5 20-apt-nvattest-2.0.0.txt
hash -r
linkage 21-v2-linkage.txt "installed $V20 from the NVIDIA repository"
cat 21-v2-linkage.txt

say "7. nvattest 2.0.0, GPU, local verifier"
cap_start 22-v2.pcap
nvrun 22-v2-gpu-local.txt attest --device gpu --verifier local --log-level debug
cap_stop

say "8. nvattest 2.0.0, GPU, remote verifier (NRAS)"
nvrun 23-v2-gpu-remote.txt attest --device gpu --verifier remote --log-level debug

say "9. nvattest 2.0.0 under strace"
traced 24-v2-strace.txt 24-v2-strace-run.txt attest --device gpu --verifier local --log-level debug

say "10. nvattest 2.0.0 with --tls-ca-cert / --tls-ca-path / OCSP over HTTP"
nvrun 25-v2-gpu-local-tls-ca-cert.txt attest --device gpu --verifier local --log-level debug --tls-ca-cert /etc/ssl/certs/ca-certificates.crt
nvrun 26-v2-gpu-local-tls-ca-path.txt attest --device gpu --verifier local --log-level debug --tls-ca-path /etc/ssl/certs
nvrun 27-v2-gpu-local-ocsp-http.txt attest --device gpu --verifier local --log-level debug --ocsp-url http://ocsp.ndis.nvidia.com

say "11. ClientHello summaries from the packet captures"
sudo -n chmod 644 ./*.pcap 2>/dev/null
python3 /tmp/parse_tls.py 11-curl-reference.pcap 12-baseline.pcap 22-v2.pcap > 28-clienthello-summary.txt 2>&1
cat 28-clienthello-summary.txt

say "12. pack"
sudo -n chown -R "$(id -u):$(id -g)" "$OUT"
tar czf /tmp/cap153.tgz -C /tmp cap153
ls -l /tmp/cap153.tgz
echo "=== END ==="
