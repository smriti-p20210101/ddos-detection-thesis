#!/bin/bash
# Cheap forensic scan across a sample of the wider 250-file chunk (every
# 10th file from _040 to _240) to check for real SYN-flood and real
# UDP-amplification (PortMap/NetBIOS/LDAP/MSSQL reflection ports) signatures
# BEFORE committing to a full re-extraction at a larger file-count scope.
# One tshark field-export pass per file (not multiple filtered passes) to
# keep this fast -- everything else is computed from that single pass.
set -e
SAMPLE_DIR="/mnt/d/Smriti PhD/extracted_sample"
OUT="/tmp/wider_scan_results.txt"
> "$OUT"

for i in 40 50 60 70 80 90 100 110 120 130 140 150 160 170 180 190 200 210 220 230 240; do
  FNAME="SAT-01-12-2018_0${i}"
  FPATH="$SAMPLE_DIR/$FNAME"
  if [ ! -f "$FPATH" ]; then
    echo "[scan] $FNAME not yet extracted, pulling from zip..."
    (cd "$SAMPLE_DIR" && unzip -o -q "/mnt/d/Smriti PhD/PCAP-01-12_0-0249.zip" "$FNAME")
  fi
  echo "=== $FNAME ===" | tee -a "$OUT"
  tshark -r "$FPATH" -T fields -e ip.src -e tcp.flags.syn -e tcp.flags.ack -e tcp.dstport -e udp.dstport -e ip.proto 2>/dev/null | \
  awk -F'\t' '
    {
      src=$1; syn=$2; ack=$3; tport=$4; uport=$5; proto=$6
      if (proto=="6") { tcp_total++; if (syn=="True" && ack=="False") { syn_only[src]++; syn_only_total++ } }
      if (proto=="17") {
        udp_total++
        if (uport=="111") { portmap[src]++ }
        else if (uport=="137" || uport=="138" || uport=="139") { netbios[src]++ }
        else if (uport=="389") { ldap[src]++ }
        else if (uport=="1433") { mssql[src]++ }
      }
    }
    END {
      printf "tcp_total=%d udp_total=%d syn_only_total=%d\n", tcp_total, udp_total, syn_only_total
      print "--- top SYN-only (no ACK) sources ---"
      for (s in syn_only) print syn_only[s], s | "sort -rn | head -5"
      close("sort -rn | head -5")
      print "--- portmap(111) sources ---"
      for (s in portmap) print portmap[s], s | "sort -rn | head -3"
      close("sort -rn | head -3")
      print "--- netbios(137-139) sources ---"
      for (s in netbios) print netbios[s], s | "sort -rn | head -3"
      close("sort -rn | head -3")
      print "--- ldap(389) sources ---"
      for (s in ldap) print ldap[s], s | "sort -rn | head -3"
      close("sort -rn | head -3")
      print "--- mssql(1433) sources ---"
      for (s in mssql) print mssql[s], s | "sort -rn | head -3"
      close("sort -rn | head -3")
    }
  ' | tee -a "$OUT"
done

echo "[scan] done, full results in $OUT"
