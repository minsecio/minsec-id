systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ]; then
    # Upgrade: a running monitor restarts on the new binary.
    systemctl try-restart minsec-id.service >/dev/null 2>&1 || :
fi
