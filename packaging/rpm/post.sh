systemd-tmpfiles --create minsec-id.conf >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -eq 1 ]; then
    systemctl enable --now minsec-id-scan.timer minsec-id-scan-full.timer minsec-id-sync.timer >/dev/null 2>&1 || :
    echo "Real-time monitoring is optional: systemctl enable --now minsec-id"
    echo "The crowd (minsec.io) is opt-in: see /usr/share/doc/minsec-id/sync.toml.example"
fi
