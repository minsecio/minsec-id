# Fish completion for minsec-id.
#
# Subcommands and options are static; check ids come from `minsec-id checks`
# and findings from `minsec-id findings` at completion time. Data queries
# fail silently, e.g. when the state directory is not readable.

# Print the subcommand on the command line, if any.
function __minsec_id_subcommand
    set -l tokens (commandline -opc)
    set -e tokens[1]
    argparse -s c/config-dir= json h/help V/version -- $tokens 2>/dev/null
    or return 1
    set -q argv[1]
    and echo $argv[1]
end

function __minsec_id_needs_command
    not __minsec_id_subcommand >/dev/null
end

# True if the subcommand on the command line is one of the arguments.
function __minsec_id_using
    set -l cmd (__minsec_id_subcommand)
    or return 1
    contains -- $cmd $argv
end

# True if the current token is positional argument number $argv[1] of the
# subcommand. Option values are skipped using the union of all option specs.
function __minsec_id_positional
    set -l want $argv[1]
    set -l tokens (commandline -opc)
    set -e tokens[1]
    argparse -s c/config-dir= json h/help V/version -- $tokens 2>/dev/null
    or return 1
    set -e argv[1]
    argparse -i c/config-dir= json h/help q/quiet full quick check= all severity= reason= reset n/last= -- $argv 2>/dev/null
    or return 1
    test (count $argv) -eq (math $want - 1)
end

# Print --config-dir DIR from the command line so data queries look at the
# same configuration the user is about to operate on.
function __minsec_id_config_args
    set -l tokens (commandline -opc)
    set -l i 2
    while test $i -le (count $tokens)
        switch $tokens[$i]
            case -c --config-dir
                if set -q tokens[(math $i + 1)]
                    printf '%s\n' --config-dir $tokens[(math $i + 1)]
                end
                return
            case '--config-dir=*'
                printf '%s\n' --config-dir (string replace -- '--config-dir=' '' $tokens[$i])
                return
        end
        set i (math $i + 1)
    end
end

# Check ids with descriptions; $argv[1] selects all, enabled, or disabled.
function __minsec_id_checks
    set -l cmd (commandline -opc)[1]
    command $cmd (__minsec_id_config_args) checks 2>/dev/null | awk -v want=$argv[1] '
        $1 == "*" { if (want == "disabled") next; n = $2; s = 4 }
        $1 != "*" { if (want == "enabled") next; n = $1; s = 3 }
        { d = ""; for (i = s; i <= NF; i++) d = d (i > s ? " " : "") $i; print n "\t" d }'
end

# Findings as check:subject keys; $argv[1] is open or all.
function __minsec_id_findings
    set -l cmd (commandline -opc)[1]
    set -l all
    test "$argv[1]" = all; and set all --all
    command $cmd (__minsec_id_config_args) findings $all 2>/dev/null | awk '{ print $3 }'
end

# Accept rules in effect.
function __minsec_id_accepted
    set -l cmd (commandline -opc)[1]
    command $cmd (__minsec_id_config_args) findings --all 2>/dev/null | sed -n 's/.*(accepted: \(.*\))$/\1/p' | sort -u
end

set -l subcommands scan status findings show accept unaccept verify baseline checks enable disable inspect check events help

complete -c minsec-id -f
complete -c minsec-id -s c -l config-dir -x -a '(__fish_complete_directories)' -d 'Configuration directory'
complete -c minsec-id -l json -d 'Machine-readable JSON output'
complete -c minsec-id -s h -l help -d 'Print help'
complete -c minsec-id -n __minsec_id_needs_command -s V -l version -d 'Print version'

complete -c minsec-id -n __minsec_id_needs_command -a scan -d 'Run checks'
complete -c minsec-id -n __minsec_id_needs_command -a status -d 'Last scan and open findings'
complete -c minsec-id -n __minsec_id_needs_command -a findings -d 'List open findings'
complete -c minsec-id -n __minsec_id_needs_command -a show -d 'Show one finding in full'
complete -c minsec-id -n __minsec_id_needs_command -a accept -d 'Accept a finding'
complete -c minsec-id -n __minsec_id_needs_command -a unaccept -d 'Remove an accept rule'
complete -c minsec-id -n __minsec_id_needs_command -a verify -d 'Verify a file or package against the package database'
complete -c minsec-id -n __minsec_id_needs_command -a baseline -d 'Show or reset the recorded baselines'
complete -c minsec-id -n __minsec_id_needs_command -a checks -d 'List checks'
complete -c minsec-id -n __minsec_id_needs_command -a enable -d 'Enable a check'
complete -c minsec-id -n __minsec_id_needs_command -a disable -d 'Disable a check'
complete -c minsec-id -n __minsec_id_needs_command -a inspect -d 'Report host capabilities, configuration sources, and checks'
complete -c minsec-id -n __minsec_id_needs_command -a check -d 'Validate configuration'
complete -c minsec-id -n __minsec_id_needs_command -a events -d 'Print the findings log'
complete -c minsec-id -n __minsec_id_needs_command -a help -d 'Print help for a subcommand'

complete -c minsec-id -n '__minsec_id_using scan' -l full -d 'Run every enabled check, including ones that read file contents'
complete -c minsec-id -n '__minsec_id_using scan' -l quick -d 'Run only cheap checks'
complete -c minsec-id -n '__minsec_id_using scan baseline' -l check -x -a '(__minsec_id_checks all)' -d 'Only this check'
complete -c minsec-id -n '__minsec_id_using scan' -s q -l quiet -d 'Print nothing'
complete -c minsec-id -n '__minsec_id_using findings' -l all -d 'Include accepted findings'
complete -c minsec-id -n '__minsec_id_using findings' -l severity -x -a 'info low medium high critical' -d 'Minimum severity'
complete -c minsec-id -n '__minsec_id_using show; and __minsec_id_positional 1' -a '(__minsec_id_findings all)'
complete -c minsec-id -n '__minsec_id_using accept' -l reason -x -d 'Why it is accepted'
complete -c minsec-id -n '__minsec_id_using accept; and __minsec_id_positional 1' -a '(__minsec_id_findings open)'
complete -c minsec-id -n '__minsec_id_using unaccept; and __minsec_id_positional 1' -a '(__minsec_id_accepted)'
complete -c minsec-id -n '__minsec_id_using verify; and __minsec_id_positional 1' -F
complete -c minsec-id -n '__minsec_id_using baseline' -l reset -d 'Forget the baselines'
complete -c minsec-id -n '__minsec_id_using enable; and __minsec_id_positional 1' -a '(__minsec_id_checks disabled)'
complete -c minsec-id -n '__minsec_id_using disable; and __minsec_id_positional 1' -a '(__minsec_id_checks enabled)'
complete -c minsec-id -n '__minsec_id_using events' -s n -l last -x -d 'Number of events to print'
complete -c minsec-id -n '__minsec_id_using help; and __minsec_id_positional 1' -a "$subcommands"
