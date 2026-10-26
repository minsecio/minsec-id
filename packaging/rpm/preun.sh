if [ $1 -eq 0 ]; then
    systemctl --no-reload disable --now minsec-id.service minsec-id-scan.timer minsec-id-scan-full.timer minsec-id-sync.timer >/dev/null 2>&1 || :
fi
