# Fish completion for minsec-id-sync. All values are static.

function __minsec_id_sync_subcommand
    set -l tokens (commandline -opc)
    set -e tokens[1]
    argparse -s c/config= h/help V/version -- $tokens 2>/dev/null
    or return 1
    set -q argv[1]
    and echo $argv[1]
end

function __minsec_id_sync_needs_command
    not __minsec_id_sync_subcommand >/dev/null
end

function __minsec_id_sync_using
    set -l cmd (__minsec_id_sync_subcommand)
    or return 1
    contains -- $cmd $argv
end

complete -c minsec-id-sync -f
complete -c minsec-id-sync -s c -l config -r -F -d 'Configuration file'
complete -c minsec-id-sync -s h -l help -d 'Print help'
complete -c minsec-id-sync -n __minsec_id_sync_needs_command -s V -l version -d 'Print version'

complete -c minsec-id-sync -n __minsec_id_sync_needs_command -a enroll -d 'Generate a key (first run) and enroll with the server'
complete -c minsec-id-sync -n __minsec_id_sync_needs_command -a report -d 'Report open finding counts (also the heartbeat)'
complete -c minsec-id-sync -n __minsec_id_sync_needs_command -a check -d 'Ask the crowd about modified package files'
complete -c minsec-id-sync -n __minsec_id_sync_needs_command -a run -d 'Enroll if needed, report, then check'
complete -c minsec-id-sync -n __minsec_id_sync_needs_command -a status -d 'Show enrollment and crowd state'
complete -c minsec-id-sync -n __minsec_id_sync_needs_command -a help -d 'Print help for a subcommand'
complete -c minsec-id-sync -n '__minsec_id_sync_using help' -a 'enroll report check run status help'
