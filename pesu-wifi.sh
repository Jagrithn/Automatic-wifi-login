#!/bin/bash
# PESU Wi-Fi auto sign-in helper
# - Stores credentials in macOS Keychain only (never in this file or logs)
# - Sends credentials ONLY to the hostel portal: https://rr.pes.edu:8090/login.xml
# - No retry loops, no credential guessing, no device-identifier changes

set -u

umask 077

# ---- Configuration ---------------------------------------------------------

HOST="rr.pes.edu"
PORT="8090"
BASE="https://${HOST}:${PORT}"
PAGE_URL="${BASE}/httpclient.html"
LOGIN_URL="${BASE}/login.xml"
CAPTIVE_URL="http://captive.apple.com/hotspot-detect.html"

SVC_PRIMARY="pesu-wifi-primary"
SVC_FALLBACK="pesu-wifi-fallback"

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)"
STATE_DIR="${SCRIPT_DIR}/state"
mkdir -p "${STATE_DIR}" 2>/dev/null
chmod 700 "${STATE_DIR}" 2>/dev/null
LOG_FILE="${STATE_DIR}/pesu-wifi.log"
COOLDOWN_FILE="${STATE_DIR}/cooldown_until"
LAST_FILE="${STATE_DIR}/last_result"

COOLDOWN_LIMIT=1800      # 30 minutes after a device/session limit
COOLDOWN_REJECT=600      # 10 minutes after an ordinary rejection (e.g. wrong password)
COOLDOWN_TRANSIENT=300   # 5 minutes after a transport/parse error
COOLDOWN_NOCREDS=3600    # 1 hour if credentials are missing (remind, don't spam)
MAX_LOG_LINES=400

VERBOSE=0
FORCE=0

# ---------------------------------------------------------------------------

log() {
    local line;
    line="$(date '+%Y-%m-%d %H:%M:%S')  $(scrub "$*")"
    if [ "${VERBOSE}" = "1" ]; then printf '%s\n' "$line"; fi
    printf '%s\n' "$line" >> "${LOG_FILE}"
    rotate_log
}

scrub() {
    printf '%s\n' "$*" | sed -e 's/password=[^&[:space:]]\{0,40\}/password=<scrubbed>/g'
}

rotate_log() {
    [ -f "${LOG_FILE}" ] || return 0
    [ "$(wc -l < "${LOG_FILE}")" -gt "${MAX_LOG_LINES}" ] || return 0
    local keep; keep=$((MAX_LOG_LINES / 2))
    tail -n "${keep}" "${LOG_FILE}" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "${LOG_FILE}"
}

notify() {
    # $1 = title, $2 = message
    osascript -e "display notification \"$2\" with title \"$1\"" >/dev/null 2>&1
}

urlencode() {
    perl -Mstrict -we 'use bytes; my $s = $ARGV[0]; $s =~ s/([^A-Za-z0-9\-_.~])/sprintf("%%%02X", ord($1))/eg; print $s' "$1"
}

xmltag() {
    # $1 = tag name, $2 = xml text
    perl -Mstrict -we 'my ($t, $x) = @ARGV; if ($x =~ m{<$t>(.*?)</$t>}s) { print $1 }' "$1" "$2"
}

now_epoch() { date +%s; }

mark_cooldown() {
    printf '%s\n' "$(( $(now_epoch) + $1 ))" > "${COOLDOWN_FILE}"
    log "cooldown set for $1s"
}

cooldown_remaining() {
    [ -f "${COOLDOWN_FILE}" ] || { printf '0'; return 0; }
    local until_ts; until_ts="$(cat "${COOLDOWN_FILE}" 2>/dev/null)"
    [ -n "${until_ts}" ] || { printf '0'; return 0; }
    local r; r=$(( until_ts - $(now_epoch) ))
    [ "$r" -gt 0 ] && printf '%s' "$r" || printf '0'
}

# Are we already online? (macOS/Apple captive-portal probe.)
is_online() {
    local body
    body="$(curl -sS --max-time 6 "${CAPTIVE_URL}" 2>/dev/null)"
    case "${body}" in
        *Success*) return 0 ;;
        *) return 1 ;;
    esac
}

# Are we on the PESU network? (SSID is hidden on modern macOS, so use DNS + portal reachability.)
on_pesu_network() {
    local ips priv code
    ips="$(dig +short "${HOST}" 2>/dev/null; dscacheutil -q host -a name "${HOST}" 2>/dev/null | awk '/ip_address/{print $2}')"
    priv="$(printf '%s\n' "${ips}" | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' | head -1)"
    [ -n "${priv}" ] || return 1
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "${PAGE_URL}" 2>/dev/null)"
    [ "${code}" = "200" ] || return 1
    return 0
}

# Read stored credentials for a given service into G_USER / G_PASS.
get_creds() {
    local svc="$1"
    G_USER="$(security find-generic-password -s "${svc}" 2>/dev/null \
| sed -n 's/^ *"acct"<blob>="\(.*\)"$/\1/p')"
    [ -n "${G_USER:-}" ] || return 1
    G_PASS="$(security find-generic-password -s "${svc}" -w 2>/dev/null)"
    [ -n "${G_PASS:-}" ] || return 1
    return 0
}

# One sign-in transaction against the portal. Returns:
#   0  = LIVE (signed in)
#   12 = rejected, message contains a device/session-limit signal
#   13 = rejected for some other reason
#   10 = no credentials stored
#   11 = empty/unparseable response
#   14 = CHALLENGE could not be completed
do_login() {
    local svc="$1" jar body a encu encp tmpmsg resp st state msgs
    if ! get_creds "${svc}"; then
        log "no credentials found for service '${svc}'"
        return 10
    fi

    jar="$(mktemp "${STATE_DIR}/jar.XXXXXX")"
    body="$(mktemp "${STATE_DIR}/body.XXXXXX")"
    chmod 600 "${jar}" "${body}" 2>/dev/null

    curl -sS --max-time 10 -c "${jar}" -o /dev/null "${PAGE_URL}" 2>/dev/null

    a="$(( $(now_epoch) * 1000 ))"
    encu="$(urlencode "${G_USER}")"
    encp="$(urlencode "${G_PASS}")"
    printf 'username=%s&password=%s&mode=191&producttype=0&a=%s' "${encu}" "${encp}" "${a}" > "${body}"

    resp="$(curl -sS --max-time 15 -b "${jar}" -c "${jar}" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -H "Origin: ${BASE}" \
        -H "Referer: ${PAGE_URL}" \
        -A 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/154.0.0.0 Safari/537.36' \
        --data-binary "@${body}" \
        "${LOGIN_URL}" 2>/dev/null)"

    # The portal can reply with a CHALLENGE that requires one follow-up POST
    # carrying its own state token. Hard cap: 2 POSTs, then stop.
    for attempt in 1 2; do
        st="$(xmltag status "${resp}")"
        [ -n "${st}" ] || { rm -f "${jar}" "${body}"; log "empty/unparseable portal response"; return 11; }
        case "${st}" in
            LIVE)
                msgs="$(xmltag message "${resp}")"
                rm -f "${jar}" "${body}"
                log "portal says LIVE (${svc})"
                G_RESULT_MSG="${msgs}"
                return 0
                ;;
            CHALLENGE)
                local state
                state="$(xmltag state "${resp}")"
                if [ -z "${state}" ]; then
                    rm -f "${jar}" "${body}"
                    log "CHALLENGE without state token"
                    return 14
                fi
                [ "${attempt}" = "1" ] || { rm -f "${jar}" "${body}"; log "CHALLENGE loop capped"; return 14; }
                printf 'username=%s&password=%s&mode=191&producttype=0&a=%s&state=%s' \
                    "${encu}" "${encp}" "$(( $(now_epoch) * 1000 ))" "${state}" > "${body}"
                log "portal requested CHALLENGE follow-up"
                resp="$(curl -sS --max-time 15 -b "${jar}" -c "${jar}" \
                    -H 'Content-Type: application/x-www-form-urlencoded' \
                    -H "Origin: ${BASE}" \
                    -H "Referer: ${PAGE_URL}" \
                    -A 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/154.0.0.0 Safari/537.36' \
                    --data-binary "@${body}" \
                    "${LOGIN_URL}" 2>/dev/null)"
                ;;
            *)
                msgs="$(xmltag message "${resp}")"
                rm -f "${jar}" "${body}"
                log "portal rejection (${svc}): $(scrub "${msgs}")"
                G_RESULT_MSG="${msgs}"
                if [ -n "${msgs}" ] && printf '%s' "${msgs}" | grep -qiE 'limit|maximum|exceed|too many|concurrent|already logged|already in use|session|device'; then
                    return 12
                fi
                return 13
                ;;
        esac
    done
    rm -f "${jar}" "${body}"
    return 11
}

is_limit_message() {
    printf '%s' "$1" | grep -qiE 'limit|maximum|exceed|too many|concurrent|already logged|already in use|session|device'
}

record_last() {
    printf '%s  %s\n' "$(now_epoch)" "$1" > "${LAST_FILE}"
}

run_once() {
    local rc remaining_up
    log "PESU Wi-Fi helper started (verbose=${VERBOSE}, force=${FORCE})"

    if is_online; then
        log "already online; nothing to do"
        record_last "online"
        [ "${VERBOSE}" = "1" ] && { echo "Already online - no sign-in needed."; }
        return 0
    fi

    if ! on_pesu_network; then
        log "not on the ${HOST} network; nothing to do"
        record_last "not-on-network"
        [ "${VERBOSE}" = "1" ] && { echo "You don't appear to be on the PESU Wi-Fi network (${HOST} unreachable/not in campus range)."; }
        return 0
    fi

    remaining_up="$(cooldown_remaining)"
    if [ "${remaining_up}" -gt 0 ] && [ "${FORCE}" = "0" ]; then
        log "cooldown active (${remaining_up}s left); skipping"
        [ "${VERBOSE}" = "1" ] && { echo "A previous attempt failed. Waiting ${remaining_up}s before trying again (or use --force)."; }
        return 0
    fi

    do_login "${SVC_PRIMARY}"
    rc=$?
    case ${rc} in
        0)
            log "sign-in OK with primary credential"
            record_last "ok-primary"
            [ "${VERBOSE}" = "1" ] && echo "Signed in with your primary credential."
            notify "PESU Wi-Fi" "Signed in ($(display_user "${SVC_PRIMARY}"))."
            return 0
            ;;
        12)
            log "primary hit a device/session limit; trying fallback once"
            do_login "${SVC_FALLBACK}"
            rc=$?
            case ${rc} in
                0)
                    log "fallback credential signed in"
                    record_last "ok-fallback"
                    [ "${VERBOSE}" = "1" ] && echo "Primary is at its limit. Signed in with the fallback credential instead."
                    notify "PESU Wi-Fi" "Limit on main ID. Sign-in done with fallback ID."
                    return 0
                    ;;
                12)
                    log "fallback also at device/session limit"
                    record_last "limit-both"
                    mark_cooldown "${COOLDOWN_LIMIT}"
                    [ "${VERBOSE}" = "1" ] && { echo "Device/session limit: this leaf credential is at its device limit."; }
                    notify "PESU Wi-Fi - device limit" "Sign in on the other device / sign it out, or email itteam.rr@pes.edu."
                    return 0
                    ;;
                10)
                    mark_cooldown "${COOLDOWN_LIMIT}"
                    record_last "limit-primary"
                    [ "${VERBOSE}" = "1" ] && echo "Device/session limit on your main ID (no fallback credential stored)."
                    notify "PESU Wi-Fi - device limit" "Main ID at device limit. Sign out the other device or email itteam.rr@pes.edu."
                    return 0
                    ;;
                *)
                    mark_cooldown "${COOLDOWN_REJECT}"
                    record_last "fallback-rejected"
                    [ "${VERBOSE}" = "1" ] && { echo "Fallback credential was also rejected by the portal."; }
                    notify "PESU Wi-Fi" "Fallback ID rejected too. Check it or contact itteam.rr@pes.edu."
                    return 0
                    ;;
            esac
            ;;
        13)
            mark_cooldown "${COOLDOWN_REJECT}"
            record_last "rejected"
            [ "${VERBOSE}" = "1" ] && { echo "Sign-in rejected by the portal: $(scrub "${G_RESULT_MSG:-no message}")"; }
            notify "PESU Wi-Fi" "sign-in rejected. Check the saved credentials or contact itteam.rr@pes.edu."
            return 0
            ;;
        10)
            mark_cooldown "${COOLDOWN_NOCREDS}"
            record_last "no-creds"
            notify "PESU Wi-Fi" "No credentials saved. Run: pesu-wifi.sh --setup"
            return 0
            ;;
        *)
            mark_cooldown "${COOLDOWN_TRANSIENT}"
            record_last "transient-error"
            [ "${VERBOSE}" = "1" ] && { echo "Portal did not return a usable response. Will retry after the cooldown."; }
            return 0
            ;;
    esac
}

display_user() {
    local u
    u="$(security find-generic-password -s "$1" 2>/dev/null | sed -n 's/^ *"acct"<blob>="\(.*\)"$/\1/p')"
    if [ -n "${u}" ]; then
        printf '%s' "${u}"
        if [ "${#u}" -gt 3 ]; then printf ' (masked: %s***)' "${u:0:2}"; fi
    else
        printf '%s' "(none stored)"
    fi
}

do_setup() {
    local u1 p1 p2 u2 a1 a2
    echo "=== PESU Wi-Fi portal credential setup ==="
    echo "(Saved only to your macOS Keychain: services '${SVC_PRIMARY}' / '${SVC_FALLBACK}')"
    echo
    echo "Primary username (your EMPID/SRN):"
    IFS= read -r u1
    [ -n "${u1}" ] || { echo "username cannot be empty; aborting."; return 1; }
    echo "Primary password (hidden):"
    stty -echo 2>/dev/null; IFS= read -r p1; stty echo 2>/dev/null; echo
    echo "Primary password again:"
    stty -echo 2>/dev/null; IFS= read -r p2; stty echo 2>/dev/null; echo
    [ -n "${p1}" ] || { echo "password cannot be empty; aborting."; return 1; }
    [ "${p1}" = "${p2}" ] || { echo "passwords did not match; aborting."; return 1; }

    if security add-generic-password -U -s "${SVC_PRIMARY}" -a "${u1}" -w 2>/dev/null <<HEREDOC
${p1}
${p1}
HEREDOC
    then
        echo "Primary credential stored (service '${SVC_PRIMARY}')."
    else
        echo "ERROR: could not store primary credential in Keychain."
        return 1
    fi

    echo
    echo "Fallback username - used ONLY when the primary hits a device/session limit."
    echo "Leave blank to skip:"
    IFS= read -r u2
    if [ -n "${u2}" ]; then
        echo "Fallback password (hidden):"
        stty -echo 2>/dev/null; IFS= read -r a1; stty echo 2>/dev/null; echo
        echo "Fallback password again:"
        stty -echo 2>/dev/null; IFS= read -r a2; stty echo 2>/dev/null; echo
        [ -n "${a1}" ] || { echo "password cannot be empty; fallback skipped."; return 0; }
        [ "${a1}" = "${a2}" ] || { echo "passwords did not match; fallback skipped."; return 0; }
        if security add-generic-password -U -s "${SVC_FALLBACK}" -a "${u2}" -w 2>/dev/null <<HEREDOC
${a1}
${a1}
HEREDOC
        then
            echo "Fallback credential stored (service '${SVC_FALLBACK}')."
        else
            echo "ERROR: could not store fallback credential in Keychain."
        fi
    else
        echo "No fallback credential stored."
    fi
    echo
    echo "Done. Run '${0} --status' or re-run to sign in now."
    return 0
}

do_install() {
    local plist="${STATE_DIR}/../com.local.pesu-wifi.plist"
    plist="$SCRIPT_DIR/com.local.pesu-wifi.plist"
    cat > "${plist}" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.local.pesu-wifi</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${SCRIPT_DIR}/pesu-wifi.sh</string>
        <string>--auto</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>60</integer>
    <key>WatchPaths</key>
    <array>
        <string>/Library/Preferences/SystemConfiguration/preferences.plist</string>
        <string>/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist</string>
    </array>
    <key>StandardOutPath</key>
    <string>${STATE_DIR}/launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>${STATE_DIR}/launchd.err.log</string>
</dict>
</plist>
PLISTEOF
    mkdir -p "$HOME/Library/LaunchAgents"
    cp -f "${plist}" "$HOME/Library/LaunchAgents/com.local.pesu-wifi.plist"
    chmod 644 "$HOME/Library/LaunchAgents/com.local.pesu-wifi.plist"
    plutil -lint "$HOME/Library/LaunchAgents/com.local.pesu-wifi.plist" >/dev/null || { echo "plist failed lint"; return 1; }
    launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.local.pesu-wifi.plist" 2>/dev/null \
        || launchctl load -w "$HOME/Library/LaunchAgents/com.local.pesu-wifi.plist" 2>/dev/null
    launchctl kickstart -k "gui/$(id -u)/com.local.pesu-wifi" 2>/dev/null
    echo "Installed. Autostarts on login + every 60s + when the network changes."
    echo "Verifying credentials are stored:"
    echo "  primary : $(display_user "${SVC_PRIMARY}")"
    echo "  fallback: $(display_user "${SVC_FALLBACK}")"
    return 0
}

do_uninstall() {
    local plist="$HOME/Library/LaunchAgents/com.local.pesu-wifi.plist"
    echo "Removing PESU Wi-Fi helper..."
    launchctl bootout "gui/$(id -u)/com.local.pesu-wifi" 2>/dev/null
    launchctl unload "${plist}" 2>/dev/null
    rm -f "${plist}"
    security delete-generic-password -s "${SVC_PRIMARY}" >/dev/null 2>&1 && echo "Removed primary credential from Keychain."
    security delete-generic-password -s "${SVC_FALLBACK}" >/dev/null 2>&1 && echo "Removed fallback credential from Keychain."
    echo "Done. You can now delete the folder: rm -rf ${SCRIPT_DIR}"
    return 0
}

do_status() {
    local rem
    echo "=== PESU Wi-Fi helper status ==="
    if is_online; then echo "connection : online (no sign-in needed)"; else echo "connection : offline/captive"; fi
    if on_pesu_network; then echo "on network : yes (${HOST}:${PORT} reachable)"; else echo "on network : no (not on ${HOST})"; fi
    rem="$(cooldown_remaining)"
    if [ "${rem}" -gt 0 ]; then echo "cooldown   : active (~$((rem/60)) min left)"; else echo "cooldown   : none"; fi
    echo "primary ID : $(display_user "${SVC_PRIMARY}")"
    echo "fallback ID: $(display_user "${SVC_FALLBACK}")"
    echo "last result: $(cat "${LAST_FILE}" 2>/dev/null || echo never)"
    echo "log tail   : $(tail -n 5 "${LOG_FILE}" 2>/dev/null || echo none)"
    return 0
}

usage() {
    cat <<USAGE
PESU Wi-Fi helper

Usage:
  pesu-wifi.sh --setup      one-time: save primary (+ optional fallback) credentials to Keychain
  pesu-wifi.sh --once       run one sign-in manually in this terminal (verbose)
  pesu-wifi.sh --auto       run in quiet auto mode (used by the launchd agent)
  pesu-wifi.sh --status     show connection/credential/cooldown status
  pesu-wifi.sh --install    create + load the launchd agent (auto sign-in)
  pesu-wifi.sh --uninstall  remove the agent and the saved credentials
  pesu-wifi.sh --force      (with --once) ignore an active cooldown
  pesu-wifi.sh --help       this help

Credentials are stored ONLY in the macOS Keychain and sent ONLY to
https://${HOST}:${PORT}. No retries beyond one transaction, no fallback except
on a device/session-limit message, no device-identifier changes.
USAGE
}

# ---- Main ------------------------------------------------------------------

case "${1:-}" in
    --setup)     do_setup ;;
    --once)      VERBOSE=1; FORCE=0; run_once ;;
    --force)     VERBOSE=1; FORCE=1; run_once ;;
    --auto)      VERBOSE=0; FORCE=0; run_once ;;
    --status)    do_status ;;
    --install)   do_install ;;
    --uninstall) do_uninstall ;;
    --help|-h)   usage ;;
    *)           usage ;;
esac

# Best-effort cleanup of any secrets still in memory.
unset G_USER G_PASS G_RESULT_MSG p1 p2 a1 a2 2>/dev/null || true
exit 0