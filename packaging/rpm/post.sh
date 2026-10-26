systemd-tmpfiles --create minsec-id.conf >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -eq 1 ]; then
    systemctl enable --now minsec-id-scan.timer minsec-id-scan-full.timer >/dev/null 2>&1 || :
fi
