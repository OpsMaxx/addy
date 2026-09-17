#!/usr/bin/env sh
#
# addy installer. Fetch and run:
#
#   curl -fsSL https://get.opsmaxx.dev/addy/install.sh | sh
#   curl -fsSL https://get.opsmaxx.dev/addy/install.sh | sh -s -- --yes --domain addy.example.com
#
# WHAT BREAKS IF THE PREFLIGHT IS SKIPPED
#
# certmagic obtains its certificate with an ACME HTTP-01 challenge, which needs
# (a) DNS for the domain already resolving to THIS box, publicly, and (b) port
# 80 reachable from the internet -- both AT INSTALL TIME, not eventually. A box
# that fails either gets a relay that starts, binds 443, and then serves a TLS
# error to every client forever, with the real cause four layers down in a log.
# The TURN server has the same shape of problem one layer further out: a
# default-denied UDP relay range gives a daemon that reports healthy and relays
# nothing, which is the worst possible first impression.
#
# So this script REFUSES WITH THE REASON. It does not warn and continue.
#
# THE TOP OF THIS FILE IS DELIBERATELY sh, NOT bash. A shebang is ignored when a
# script arrives on stdin, so `curl | sh` runs it under dash on every Debian
# derivative: no pipefail, no arrays, no [[. The prologue's only job is to land
# the real script on disk and re-exec it under bash -- which also fixes the
# other half of the problem, that a TRUNCATED download would otherwise execute
# whatever prefix arrived.

set -eu

ADDY_INSTALLER_URL="${ADDY_INSTALLER_URL:-https://get.opsmaxx.dev/addy/install.sh}"
ADDY_BUNDLE_URL="${ADDY_BUNDLE_URL:-https://get.opsmaxx.dev/addy}"

# The re-exec is UNCONDITIONAL, not "only when piped". Running this as
# `sh install.sh` from a file skips the pipe case but still leaves dash
# executing bash syntax two lines further down, which fails with a parse error
# that says nothing about why. So: if we are not already the re-executed bash,
# become it -- from the local file when there is one, and by downloading when
# there is not.
if [ -z "${ADDY_REEXEC:-}" ]; then
  command -v bash >/dev/null 2>&1 || { echo "addy: bash is required" >&2; exit 1; }
  if [ -f "$0" ]; then
    ADDY_REEXEC=1 exec bash "$0" "$@"
  fi
  tmp="$(mktemp)" || exit 1
  # Not retried: if the installer itself cannot be fetched there is nothing
  # sensible to fall back to, and curl's own error is the whole message.
  curl -fsSL "$ADDY_INSTALLER_URL" -o "$tmp" || {
    echo "addy: could not download the installer from $ADDY_INSTALLER_URL" >&2
    rm -f "$tmp"; exit 1
  }
  ADDY_REEXEC=1 exec bash "$tmp" "$@"
fi

# ---------------------------------------------------------------------------
# Everything below is bash, and everything below is inside a function. main is
# called on the very last line, so a partial file does nothing at all.
# ---------------------------------------------------------------------------

set -euo pipefail

ADDY_MIN_MEM_KB=1900000        # ~2 GiB, allowing for what the kernel reserves
ADDY_MIN_CPUS=2
ADDY_MIN_DISK_KB=20971520      # 20 GiB on the Docker data root
ADDY_RELAY_MIN=49160
ADDY_RELAY_MAX=49360
INSTALL_DIR="${ADDY_INSTALL_DIR:-/opt/addy}"
COMPOSE=()                     # filled in by check_docker

# NOTE on the relay range. DESIGN.md names 49152-65535, the ephemeral range
# coturn defaults to. Narrowed here, and narrowed in exactly one place:
#   - WireGuard's 51820 sits inside it, and the collision is intermittent and
#     start-order-dependent, which is the worst kind to debug.
#   - It is 16384 ports. Every firewall rule and every provider firewall form
#     scales with that number, while 200 concurrent relayed sessions is far
#     past what a single-box relay will ever see.

log()  { printf '==> %s\n' "$*"; }
warn() { printf '==> %s\n' "$*" >&2; }

# Every preflight failure comes through here, so they all read the same way and
# all name the fix.
refuse() {
  printf '\n' >&2
  printf 'addy: REFUSING TO INSTALL\n\n' >&2
  printf '  %s\n\n' "$1" >&2
  if [ "$#" -gt 1 ]; then printf '  Fix: %s\n\n' "$2" >&2; fi
  exit 1
}

# The same four attempts and 5s/15s/45s backoff as the sibling repo's
# net-retry.sh, and the same rule: the command's own output is never captured
# or silenced, because on the last attempt the underlying error is the only
# thing that explains what went wrong.
retry_network() {
  local what="$1"; shift
  local attempt=1 delay=5
  while :; do
    if "$@"; then return 0; fi
    if [ "$attempt" -ge 4 ]; then
      warn "$what failed four times; giving up"
      return 1
    fi
    warn "$what failed (attempt $attempt of 4); retrying in ${delay}s"
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 3))
  done
}

# --- preflight: the box itself ---------------------------------------------

check_root() {
  [ "$(id -u)" -eq 0 ] || refuse \
    "This installer must run as root; it writes to $INSTALL_DIR and talks to the Docker socket." \
    "sudo sh -c \"curl -fsSL $ADDY_INSTALLER_URL | sh\""
}

check_docker() {
  command -v docker >/dev/null 2>&1 || refuse \
    "Docker is not installed." \
    "curl -fsSL https://get.docker.com | sh    (then re-run this installer)"

  docker info >/dev/null 2>&1 || refuse \
    "Docker is installed but the daemon is not reachable." \
    "systemctl start docker"

  # `docker compose` (the v2 plugin) and `docker-compose` (the retired Python
  # v1) are different programs with different schema support. v1 does not
  # understand `depends_on: {condition: service_healthy}` and will start addy
  # before Garage can take a PUT -- silently, which is the problem.
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  else
    refuse \
      "The Docker Compose v2 plugin is missing. A standalone docker-compose binary is not a substitute: it ignores the healthcheck gate this deployment depends on." \
      "apt-get install docker-compose-plugin    (or this distro's equivalent)"
  fi
}

check_size() {
  local mem cpus disk root
  mem="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  cpus="$(nproc 2>/dev/null || echo 1)"
  # The Docker data root, not /, because that is where the volumes land.
  root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)"
  [ -d "$root" ] || root=/var
  disk="$(df -Pk "$root" | awk 'NR==2 {print $4}')"

  [ "$mem" -ge "$ADDY_MIN_MEM_KB" ] || refuse \
    "This box has $((mem/1024)) MiB of RAM. addy needs at least 2 GiB." \
    "Resize the VPS. Garage memory-maps its LMDB metadata store and addy holds relay buffers per session; 1 GiB boxes OOM under the first concurrent upload."

  [ "$cpus" -ge "$ADDY_MIN_CPUS" ] || refuse \
    "This box has $cpus vCPU. addy needs at least 2." \
    "Resize the VPS. One core is shared between TLS termination, the DTLS and SRTP work in the TURN path, and Garage's background scrubber, and they contend."

  [ "$disk" -ge "$ADDY_MIN_DISK_KB" ] || refuse \
    "Only $((disk/1024/1024)) GiB free on $root. addy needs at least 20 GiB." \
    "Attach or grow a volume at $root."
}

check_port_free() {
  local busy
  busy="$(ss -Hltn '( sport = :80 or sport = :443 )' 2>/dev/null || true)"
  [ -z "$busy" ] || refuse \
"Something is already listening on port 80 or 443:

$busy

addy is the only thing that binds 80 and 443 -- it runs an SNI router there and
reaches everything else over loopback." \
    "Stop the other service (nginx, caddy, apache and traefik are the usual four), then re-run."
}

# Informational, never a refusal: a local firewall that drops 80 is a cause we
# can name, but its absence proves nothing about the provider's.
check_local_firewall() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw status | grep -qE '(^80|^443|Anywhere.*(80|443))' \
      || warn "ufw is active with no rule for 80/443. The real check is below."
    ufw status | grep -q "${ADDY_RELAY_MIN}:${ADDY_RELAY_MAX}/udp" \
      || warn "ufw is active with no rule for ${ADDY_RELAY_MIN}:${ADDY_RELAY_MAX}/udp (the TURN relay range)."
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --list-ports 2>/dev/null | grep -q "${ADDY_RELAY_MIN}-${ADDY_RELAY_MAX}/udp" \
      || warn "firewalld is active with no rule for ${ADDY_RELAY_MIN}-${ADDY_RELAY_MAX}/udp (the TURN relay range)."
  fi
}

# --- preflight: DNS is live, publicly, and points here ----------------------
#
# Deliberately NOT `getent hosts`. The local resolver answers from /etc/hosts,
# from a stale cache, and from a split-horizon view -- all three of which say
# yes while the CA says no. The only question that matters is what a PUBLIC
# resolver sees, so ask one over DoH and compare it to what a public echo says
# this box's address is.

public_ip() {  # $1 = -4 or -6
  curl "$1" -fsS --max-time 10 https://www.cloudflare.com/cdn-cgi/trace \
    | awk -F= '/^ip=/ {print $2}'
}

doh_resolve() { # $1 = name, $2 = A|AAAA
  curl -fsS --max-time 10 -H 'accept: application/dns-json' \
    "https://dns.google/resolve?name=$1&type=$2" \
    | grep -o "\"data\":\"[^\"]*\"" | cut -d'"' -f4
}

check_dns() {
  local domain="$1" v4 v6 a aaaa
  v4="$(retry_network "detecting public IPv4" public_ip -4 || true)"
  v6="$(retry_network "detecting public IPv6" public_ip -6 || true)"
  [ -n "$v4$v6" ] || refuse \
    "Could not determine this box's public IP address." \
    "Check that outbound HTTPS works, then re-run."

  a="$(retry_network "resolving A $domain" doh_resolve "$domain" A || true)"
  aaaa="$(retry_network "resolving AAAA $domain" doh_resolve "$domain" AAAA || true)"

  [ -n "$a$aaaa" ] || refuse \
    "$domain does not resolve from a public resolver. The HTTP-01 challenge needs DNS to be live AT INSTALL TIME, not eventually." \
    "Create an A record for $domain pointing at ${v4:-this box}, wait for the TTL, then re-run."

  if [ -n "$a" ] && [ -n "$v4" ] && ! printf '%s\n' "$a" | grep -qx "$v4"; then
    refuse \
      "$domain resolves to $(printf '%s' "$a" | tr '\n' ' ')but this box is $v4." \
      "Point the A record at $v4, or install on the box that owns that address."
  fi

  # An AAAA record is a POSITIVE STATEMENT that IPv6 works. Let's Encrypt
  # prefers AAAA when it exists and does not silently fall back to A when it
  # times out, so an AAAA left over from a previous host is a total ACME
  # failure whose error names neither IPv6 nor the stale record.
  if [ -n "$aaaa" ] && { [ -z "$v6" ] || ! printf '%s\n' "$aaaa" | grep -qx "$v6"; }; then
    refuse \
      "$domain has an AAAA record ($(printf '%s' "$aaaa" | tr '\n' ' ')) that this box does not answer on. Let's Encrypt prefers IPv6 and will not fall back to IPv4 when the AAAA times out." \
      "Delete the AAAA record, or give this box working IPv6 at that address."
  fi
  log "DNS for $domain is live and points here"
}

# --- preflight: port 80 is reachable FROM OUTSIDE --------------------------
#
# Stated honestly, because the alternative is a check that passes on a box
# where the product does not work: a shell HERE cannot prove inbound
# reachability. Everything above rules out the causes visible locally; this
# hands the actual proof to `addy preflight`, which orders a real certificate
# from Let's Encrypt's STAGING directory. That is the only test that exercises
# the path the real order will, and its error text is what distinguishes a
# provider firewall from wrong DNS from something else on :80.
check_acme_reachable() {
  local domain="$1"
  log "proving port 80 is reachable from the internet (a real staging order)"
  # Host-networked, so it really binds this box's port 80.
  if ! docker run --rm --network host \
        "ghcr.io/opsmaxx/addy:${ADDY_VERSION:-latest}" \
        preflight -domain "$domain"; then
    refuse \
"An ACME challenge for $domain did not complete. Port 80 has to be reachable
from the internet, and this box cannot see why it is not.

The two causes a shell here cannot detect:
  * the VPS PROVIDER's firewall, which is a separate layer from the host's and
    lives in their control panel, not here -- AWS security groups, Hetzner
    Cloud firewalls, DigitalOcean cloud firewalls, and Oracle Cloud's
    default-deny ingress are the four that come up most;
  * a network appliance in front of the box." \
      "Allow inbound TCP 80 and 443 in the provider's firewall as well as the host's, then re-run."
  fi
}

# --- install ---------------------------------------------------------------

fetch_bundle() {
  mkdir -p "$INSTALL_DIR"
  local f
  for f in docker-compose.yml garage.toml; do
    retry_network "downloading $f" \
      curl -fsSL "$ADDY_BUNDLE_URL/$f" -o "$INSTALL_DIR/$f.new"
    mv "$INSTALL_DIR/$f.new" "$INSTALL_DIR/$f"
  done
  chmod 644 "$INSTALL_DIR/garage.toml"
}

gen_env() {
  local domain="$1" email="$2" env_file="$INSTALL_DIR/.env"

  # THE re-runnability rule. .env is the source of truth and is never
  # regenerated. A regenerated GARAGE_DEFAULT_SECRET_KEY is not a fresh start,
  # it is a hard Garage startup error naming a key id; and a regenerated
  # ADDY_TURN_SECRET invalidates every credential already issued to a
  # connected client.
  if [ -f "$env_file" ]; then
    log "keeping the existing $env_file (this is a re-run)"
    return 0
  fi

  log "generating secrets"
  # umask, so the file is 0600 the moment it exists rather than 0600 after a
  # chmod that a crash between the two can miss.
  ( umask 077
    cat > "$env_file" <<EOF
ADDY_DOMAIN=$domain
ADDY_ACME_EMAIL=$email
ADDY_VERSION=${ADDY_VERSION:-latest}

GARAGE_RPC_SECRET=$(openssl rand -hex 32)
GARAGE_DEFAULT_ACCESS_KEY=addy-$(openssl rand -hex 8)
GARAGE_DEFAULT_SECRET_KEY=$(openssl rand -hex 32)
GARAGE_DEFAULT_BUCKET=addy

ADDY_TURN_SECRET=$(openssl rand -hex 32)
ADDY_TURN_RELAY_MIN=$ADDY_RELAY_MIN
ADDY_TURN_RELAY_MAX=$ADDY_RELAY_MAX
EOF
  )
  chmod 600 "$env_file"
}

start() {
  # Pulled separately and retried, so a registry flake is a retry rather than a
  # half-started stack.
  retry_network "pulling images" "${COMPOSE[@]}" -f "$INSTALL_DIR/docker-compose.yml" pull
  log "starting"
  "${COMPOSE[@]}" -f "$INSTALL_DIR/docker-compose.yml" up -d --remove-orphans
}

verify() {
  local domain="$1"
  log "waiting for the relay to answer"
  # A first boot includes a real certificate order, which is not instant.
  local attempt
  for attempt in $(seq 1 30); do
    if "${COMPOSE[@]}" -f "$INSTALL_DIR/docker-compose.yml" \
         exec -T addy /addy selftest -target "$domain" -quick >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  refuse \
    "addy started but never answered on https://$domain." \
    "${COMPOSE[*]} -f $INSTALL_DIR/docker-compose.yml logs addy"
}

usage() {
  cat <<EOF
addy installer

  install.sh [--domain HOST] [--email ADDRESS] [--yes] [--relay-range MIN-MAX]

  --domain        The hostname this instance answers on. Required.
  --email         Contact address for the ACME account, so the CA can warn you
                  before a renewal fails.
  --yes, -y       Non-interactive. Requires --domain.
  --relay-range   UDP range for the TURN relay (default ${ADDY_RELAY_MIN}-${ADDY_RELAY_MAX}).

ADDY_DOMAIN and ADDY_ACME_EMAIL are read from the environment if the flags are
not given, for the configuration-management case where passing flags through
\`curl | sh -s --\` is awkward.
EOF
}

main() {
  local domain="" email="" assume_yes=0

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --domain) domain="${2:-}"; shift 2 ;;
      --email)  email="${2:-}";  shift 2 ;;
      --yes|-y) assume_yes=1; shift ;;
      --relay-range) ADDY_RELAY_MIN="${2%%-*}"; ADDY_RELAY_MAX="${2##*-}"; shift 2 ;;
      --help|-h) usage; exit 0 ;;
      *) refuse "Unknown option: $1" "install.sh --help" ;;
    esac
  done

  domain="${domain:-${ADDY_DOMAIN:-}}"
  email="${email:-${ADDY_ACME_EMAIL:-}}"

  if [ -z "$domain" ]; then
    # --yes alone is not enough: without a domain there is nothing to ask a CA
    # for, so it refuses rather than prompting into a pipe with no reader.
    [ "$assume_yes" -eq 0 ] || refuse \
      "--yes was given without --domain." \
      "install.sh --yes --domain addy.example.com"
    # /dev/tty, not stdin: stdin is the installer script itself when piped.
    [ -e /dev/tty ] || refuse \
      "No domain was given and there is no terminal to ask on." \
      "install.sh --yes --domain addy.example.com"
    printf 'Domain for this addy instance: ' > /dev/tty
    read -r domain < /dev/tty
  fi
  [ -n "$domain" ] || refuse "A domain is required." "install.sh --domain addy.example.com"

  check_root
  check_docker
  check_size
  check_port_free
  check_local_firewall
  check_dns "$domain"
  check_acme_reachable "$domain"

  fetch_bundle
  gen_env "$domain" "$email"
  start
  verify "$domain"

  log "done -- https://$domain"
  log "The TURN relay range ${ADDY_RELAY_MIN}-${ADDY_RELAY_MAX}/udp must be open inbound in the"
  log "provider's firewall too. It is proved by \`addy selftest\` once the relay"
  log "milestone lands; until then nothing here has tested it."
}

main "$@"
