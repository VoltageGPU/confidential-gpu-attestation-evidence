#!/usr/bin/env bash
# Follow-up: per-address reachability of the NVIDIA endpoints from this guest,
# then nvattest 2.0.0 with ocsp/rim pinned (via /etc/hosts) to the best and
# to the worst address. Outputs in /tmp/cap153b, packed into /tmp/cap153b.tgz.
set -u
export LC_ALL=C
OUT=/tmp/cap153b
rm -rf "$OUT" /tmp/cap153b.tgz
mkdir -p "$OUT" && cd "$OUT" || exit 1
N=8
say() { echo; echo "===== $(date -u +%H:%M:%S) $* ====="; }

probe_ip() {  # host ip port scheme
  local h="$1" ip="$2" port="$3" sch="$4" i
  for i in $(seq 1 "$N"); do
    curl -s -o /dev/null --connect-timeout 5 -m 8 --resolve "$h:$port:$ip" \
      -w "$h $ip:$port try=$i rc=%{exitcode} http=%{http_code} tcp=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s\n" \
      "$sch://$h/" 2>&1
  done
}

say "A. per-address probes: $N sequential curl requests per address (connect timeout 5 s, max 8 s)"
for h in ocsp.ndis.nvidia.com rim.attestation.nvidia.com nras.attestation.nvidia.com; do
  for ip in $(getent ahostsv4 "$h" | awk '{print $1}' | sort -u); do
    probe_ip "$h" "$ip" 443 https > "per-ip-$h-$ip-443.txt" &
    if [ "$h" = ocsp.ndis.nvidia.com ]; then probe_ip "$h" "$ip" 80 http > "per-ip-$h-$ip-80.txt" & fi
  done
done
wait
cat per-ip-*.txt > 30-per-address-probes.txt
{
  echo "address                                   ok/total  failures (tcp=0 means the TCP handshake never completed)"
  for f in per-ip-*.txt; do
    key=${f#per-ip-}; key=${key%.txt}
    ok=$(grep -c ' rc=0 ' "$f"); total=$(wc -l < "$f")
    fails=$(grep -v ' rc=0 ' "$f" | awk '{print $4"/"$6}' | sort | uniq -c | tr '\n' ' ')
    printf '%-42s %s/%s  %s\n' "$key" "$ok" "$total" "$fails"
  done
} > 31-per-address-summary.txt
cat 31-per-address-summary.txt

best_worst() {  # host -> "best worst" by HTTPS success count
  local f ip ok
  for f in per-ip-"$1"-*-443.txt; do
    ip=${f#per-ip-"$1"-}; ip=${ip%-443.txt}
    ok=$(grep -c ' rc=0 ' "$f")
    echo "$ok $ip"
  done | sort -n | awk 'NR==1 {w=$2} {b=$2} END {print b, w}'
}
read -r OB OW < <(best_worst ocsp.ndis.nvidia.com)
read -r RB RW < <(best_worst rim.attestation.nvidia.com)
echo "ocsp best=$OB worst=$OW ; rim best=$RB worst=$RW"

sudo -n cp /etc/hosts /tmp/hosts.orig
pinned() {  # $1 file, $2 ocsp ip, $3 rim ip
  local f="$1" rc t0
  sudo -n cp /tmp/hosts.orig /etc/hosts
  printf '%s ocsp.ndis.nvidia.com\n%s rim.attestation.nvidia.com\n' "$2" "$3" | sudo -n tee -a /etc/hosts >/dev/null
  echo "\$ sudo nvattest attest --device gpu --verifier local --log-level debug   (/etc/hosts: ocsp -> $2, rim -> $3)" > "$f"
  t0=$(date +%s%N)
  sudo -n timeout 90 nvattest attest --device gpu --verifier local --log-level debug >> "$f" 2>&1
  rc=$?
  echo "exit=$rc elapsed_ms=$(( ($(date +%s%N) - t0) / 1000000 ))" >> "$f"
  sudo -n cp /tmp/hosts.orig /etc/hosts
  echo "--- $f"
  grep -E 'rror|libcurl|SSL|TLS|successful|failed|exit=' "$f" | tail -n 20
}

say "B. nvattest 2.0.0 with ocsp and rim pinned to their best addresses"
pinned 32-v2-pinned-best.txt "$OB" "$RB"
say "C. nvattest 2.0.0 with ocsp pinned to its worst address, rim to its best"
pinned 33-v2-pinned-ocsp-worst.txt "$OW" "$RB"
say "D. nvattest 2.0.0 with rim pinned to its worst address, ocsp to its best"
pinned 34-v2-pinned-rim-worst.txt "$OB" "$RW"
cmp -s /etc/hosts /tmp/hosts.orig && echo "/etc/hosts restored"

say "E. pack"
tar czf /tmp/cap153b.tgz -C /tmp cap153b
ls -l /tmp/cap153b.tgz
echo "=== END B ==="
