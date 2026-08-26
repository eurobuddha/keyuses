#!/usr/bin/env bash
# Publish a KeyUses MiniDapp version across the whole PandaDapps store.
#
# The store was rearranged: the manifest source-of-truth is the eurobuddha/dappstore
# repo (tools/dappstore/pandadapps.json); the LIVE copy lives on the server and the
# installable *.mds.zip builds are NOT committed anywhere. The full formula:
#   1. build keyuses-<ver>.mds.zip from minidapp/ (if not already built)
#   2. upload it to           <box>:/var/www/html/panda_dapps/
#   3. point the KeyUses entry in the LIVE /var/www/html/pandadapps.json at <ver>
#   4. mirror to the store host   (/usr/local/bin/sync_store_to_sally.sh)
#   5. refresh the IPFS snapshot  (/usr/local/bin/build_ipfs_store.sh; also hourly cron)
#   6. verify both HTTP stores + the zip + the new IPFS CID
# Then, as a REMINDER printed at the end (kept out of this script so it can never
# touch the wrong repo): bump tools/dappstore/pandadapps.json to <ver> and commit it,
# so the committed manifest stays in sync with the live one.
#
# Usage:  ./scripts/publish_dappstore.sh 0.1.52   (run from the keyuses repo root)
#
# HOST is the SSH target for the eurobuddha box (eurobuddha.com resolves to the
# hetzner machine, 65.109.31.226 — same host). It defaults to the `hetzner` ssh
# alias because the bare `eurobuddha.com` ssh-config entry has historically carried
# a stale key; override with HOST=... to use another alias/host. Public file URLs
# below stay hard-coded to the eurobuddha.com domain regardless of HOST.
set -euo pipefail
VER="${1:?usage: publish_dappstore.sh <version>}"
ZIP="keyuses-${VER}.mds.zip"
HOST="${HOST:-hetzner}"
DESC="Audit your node's 64 keys for one-time-key RE-USE (stateful-signature safety)"

# Guard: the built dapp's own version must match what we're publishing, so a forgotten
# dapp.conf bump can't ship a stale build under a new version number.
CONFVER=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]*"' minidapp/dapp.conf | head -1 | sed -E 's/.*"([^"]*)"$/\1/')
[ "$CONFVER" = "$VER" ] || { echo "minidapp/dapp.conf version ($CONFVER) != $VER — bump it first"; exit 1; }

if [ ! -f "$ZIP" ]; then
  echo "1/6 build $ZIP from minidapp/"
  ( cd minidapp && zip -X "../$ZIP" dapp.conf index.html mds.js icon.svg >/dev/null )
else
  echo "1/6 using existing $ZIP"
fi

echo "2/6 upload $ZIP -> $HOST:/var/www/html/panda_dapps/"
scp -o ConnectTimeout=25 "$ZIP" "$HOST:/var/www/html/panda_dapps/"

echo "3/6 point live pandadapps.json KeyUses entry at $VER (backup written: pandadapps.json.prev)"
# Ship the editor as a file (DESC may contain apostrophes/parens that break inline quoting).
TMP_PY="$(mktemp -t keyuses_store.XXXXXX.py)"
cat > "$TMP_PY" <<PY
import json, shutil
f='/var/www/html/pandadapps.json'
shutil.copy(f, f+'.prev')
ver=$(python3 -c "import json;print(json.dumps('$VER'))")
desc=$(python3 -c "import json;print(json.dumps('''$DESC'''))")
d=json.load(open(f)); n=0
for a in d['dapps']:
    if a.get('name')=='KeyUses':
        a['file']='https://eurobuddha.com/panda_dapps/keyuses-%s.mds.zip'%ver
        a['version']=ver
        a['description']=desc
        n+=1
json.dump(d, open(f,'w'), indent=2)
print('updated KeyUses entries:', n)
PY
scp -o ConnectTimeout=25 "$TMP_PY" "$HOST:/tmp/keyuses_store_edit.py"
ssh -o ConnectTimeout=30 "$HOST" 'python3 /tmp/keyuses_store_edit.py && rm -f /tmp/keyuses_store_edit.py'
rm -f "$TMP_PY"

echo "4/6 mirror to sally"
ssh -o ConnectTimeout=60 "$HOST" '/usr/local/bin/sync_store_to_sally.sh >/dev/null 2>&1 && echo synced || echo "sync rc=$?"'

echo "5/6 refresh IPFS snapshot + IPNS (also runs hourly from cron)"
# Non-fatal: the snapshot is a mirror and cron reruns it hourly, so an IPFS hiccup
# must not fail an otherwise-published version. (A failing remote pin is expected —
# see tools/dappstore/README.md — and does not stop the local publish/IPNS.)
ssh -o ConnectTimeout=30 -o ServerAliveInterval=30 "$HOST" \
  '/usr/local/bin/build_ipfs_store.sh 2>&1 | tail -3' \
  || echo "  (IPFS step returned nonzero; hourly cron will retry)"

echo "6/6 verify"
for base in "https://eurobuddha.com" "https://store.eurobuddha.com"; do
  printf '  %s -> ' "$base"
  curl -s --max-time 15 "$base/pandadapps.json" \
    | python3 -c "import sys,json;[print(a['version'],a['file']) for a in json.load(sys.stdin)['dapps'] if a['name']=='KeyUses']"
done
printf '  zip 200? '; curl -s -o /dev/null -w '%{http_code}\n' --max-time 15 "https://eurobuddha.com/panda_dapps/$ZIP"
printf '  ipfs cid: '; curl -s --max-time 15 "https://eurobuddha.com/ipfs-cid.txt"; echo

cat <<REMIND

NEXT — keep the committed manifest in sync with live:
  In the eurobuddha/dappstore repo, set the KeyUses entry in
  tools/dappstore/pandadapps.json to version $VER + keyuses-$VER.mds.zip,
  then commit & push. The live store (above) is already updated.
REMIND
echo "done."
