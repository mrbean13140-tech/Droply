#!/bin/sh
# Сборка шаблона LXC (ostype=unmanaged). Конфиг сети — etc-landrop.json.
set -e
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o droply .
R=$(mktemp -d)
mkdir -p $R/sbin $R/etc/ssl/certs $R/dev $R/proc $R/sys $R/tmp $R/run $R/data $R/opt $R/bin
cp droply $R/sbin/init; chmod 755 $R/sbin/init; chmod 1777 $R/tmp
cat /usr/share/ca-certificates/mozilla/*.crt > $R/etc/ssl/certs/ca-certificates.crt
cp etc-landrop.json $R/etc/landrop.json
# cloudflared встраивается в шаблон (версия и SHA-256 как в init_linux.go), чтобы не зависеть от GitHub при старте
CF_VER=2026.10.7; CF_SHA=1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872
[ -f cloudflared ] || curl -sL -o cloudflared https://github.com/cloudflare/cloudflared/releases/download/$CF_VER/cloudflared-linux-amd64
echo "$CF_SHA  cloudflared" | sha256sum -c - || { echo "cloudflared: неверная контрольная сумма"; exit 1; }
install -m 755 cloudflared $R/opt/cloudflared
printf 'root:x:0:0::/:/sbin/nologin\nserve:x:1000:1000::/tmp:/sbin/nologin\ncf:x:1001:1001::/tmp:/sbin/nologin\n' > $R/etc/passwd
printf 'root:x:0:\nserve:x:1000:\ncf:x:1001:\n' > $R/etc/group
printf '127.0.0.1 localhost\n' > $R/etc/hosts; echo landrop > $R/etc/hostname; : > $R/etc/resolv.conf
tar --numeric-owner --owner=0 --group=0 -C $R -czf droply-rootfs.tar.gz .
rm -rf $R
