# Detour

A Linux desktop app (Tauri) for routing around ISP and network-level
interference, without slowing down or rerouting everything on your machine.

- **System-wide encrypted DNS (DoH)** — every lookup goes over
  DNS-over-HTTPS instead of your network's resolver, with a local resolver
  cache, provider fallback, and split-horizon routing so `.lan`/`.local`
  names stay on your own network.
- **Per-app WireGuard tunnel** — send only the apps you choose (a browser,
  Steam, a specific game) through a WireGuard tunnel; everything else on
  the machine keeps its normal connection and speed.
- **Filter bypass (TLS-record fragmentation)** — defeats SNI-based
  filtering (e.g. a network forcing YouTube Restricted Mode by reading the
  hostname from the unencrypted TLS handshake) by splitting the ClientHello
  across TLS records. No VPN, no decryption, full speed — confirmed to
  restore unfiltered results where a full WireGuard tunnel was blocked
  outright. Works via an HTTP proxy for browsers, or a per-app firewall
  redirect for anything else.
- **Diagnostics** — compares your network's resolver against DoH for a
  given domain, checks reachability, and flags known forced-restriction
  DNS answers.

Everything is scoped per-app or explicitly opt-in; nothing is silently
system-wide except the DNS layer, which is off by default and one click to
disable. Started life as a Wuthering Waves helper (hence the old `wuwa-dns`
name, still accepted for config migration); it is now general-purpose.

It resolves names. It does not touch game binaries, anti-cheat, DRM, account
regions, or publisher-side restrictions — and it cannot help with blocking that
happens below DNS (see *Is DNS actually your problem?* below).

## Layout

| Path | What it is | Privilege |
|---|---|---|
| `crates/dns-core` | DoH resolver, TTL cache, routing policy, config | none |
| `crates/dns-helper` | DNS proxy, `resolv.conf` takeover, diagnostics | **root** |
| `src-tauri` | Tauri control panel | none |
| `dist` | Front end (plain HTML/CSS/JS, no build step) | — |

The split is the point: the GUI never binds a port or writes a system file. It
starts the helper through `pkexec` and otherwise only *reads* a world-readable
status snapshot, so the privilege boundary runs one way.

## Install

```bash
packaging/install-user.sh              # build + install to ~/.local, adds a launcher entry
packaging/install-user.sh --uninstall  # remove it (config in ~/.config/detour is kept)
```

No root needed to install. Re-run after pulling changes.

## Build and run

```bash
cargo build                       # everything
cargo test --workspace            # 79 tests, no network needed
cargo tauri dev                   # GUI against the debug helper

# live DoH tests (real network)
cargo test -p dns-core --test live_doh -- --ignored --nocapture
```

## How resolution is routed

`/etc/resolv.conf` is pointed at a proxy on `127.0.0.53:53`, which decides per
query:

- **local names → your original resolver.** `.local`, `.lan`, `home.arpa`,
  single-label hostnames, and reverse lookups for RFC1918 ranges. A public
  resolver cannot answer these, so sending them upstream would break your
  router, printer, and LAN discovery.
- **everything else → DoH**, over the first provider that answers
  (Cloudflare → Quad9 → Google), with TTL-respecting caching.

Provider hostnames are pinned to literal IPs. Once we *are* the system
resolver, looking up `cloudflare-dns.com` normally would recurse into
ourselves.

### Why a proxy and not the hosts file

`/etc/hosts` has no TTL. You would pin a CDN address that later rotates, and
the game would break weeks later in a way that looks exactly like the ISP
problem you installed this to fix. It also cannot express `*.example.com`, and
its crash-safe restore is the dangerous kind — a crash mid-write corrupts the
file every process depends on for name resolution.

The proxy respects TTLs, matches suffixes, decides per query, and leaves no
persistent state: stop the process and it is over.

## Safety of the `resolv.conf` takeover

1. Every write is atomic — temp file, `fsync`, `rename`. A crash mid-write
   leaves the previous file wholly intact, never a truncated one.
2. The original is backed up and fsynced to `/var/lib/detour/` *before*
   `/etc/resolv.conf` is touched.
3. The owning PID is recorded. On the next start, a recorded takeover whose
   process is gone is detected as a crash and undone before anything else.
4. NetworkManager would otherwise rewrite `resolv.conf` on any connection
   change, so a `dns=none` drop-in is installed while active and removed on
   restore. A pre-existing drop-in is never deleted.

Recover manually at any time:

```bash
sudo ./target/debug/dns-helper status    # is anything active?
sudo ./target/debug/dns-helper restore   # put the original back
```

## Is DNS actually your problem?

DoH only helps when the interference is *in DNS*. If your ISP also filters on
SNI or destination IP, correct answers will not save you. Check before writing
any profile entry:

```bash
./target/debug/dns-helper diagnose your-game-domain.com
```

It resolves through your current resolver and through DoH, then tries to
connect to every address returned:

| Verdict | Meaning |
|---|---|
| `Healthy` | Both agree, addresses connect. Not a DNS problem. |
| `DnsInterference` | Your resolver failed or returned dead addresses; DoH's work. **This tool helps.** |
| `BlockedBeyondDns` | Both resolve, nothing connects. IP/SNI level — DNS cannot fix it. |
| `DivergentButHealthy` | Different addresses, both work. Normal CDN behaviour. |
| `ResolutionFailed` | Neither resolver answered. |

### The "system DNS" column, and what it is really testing

It tests whatever `/etc/resolv.conf` currently lists. Seeing a public resolver
there does **not** automatically mean the comparison is invalid — check what
DHCP actually handed you before assuming someone overrode it:

```bash
nmcli -f DHCP4 device show <iface> | grep -i dns   # what the ISP offered
nmcli -f ipv4.dns,ipv4.ignore-auto-dns connection show <name>   # any manual override?
```

On this network the ISP's own DHCP hands out `8.8.8.8`/`8.8.4.4`, with no
manual override configured. There is no separate "ISP resolver" behind the
gateway to point at — `10.100.32.1` does not answer on port 53 at all, so
pointing `resolv.conf` there would simply break name resolution.

### Checking for transparent port-53 interception

An ISP can hand out a legitimate resolver and still filter DNS, by silently
redirecting all port-53 traffic to its own filtering resolver. Two read-only
tests settle it:

```bash
# 1. Query an unroutable address. ANY answer proves interception.
dig @192.0.2.1 example.com +time=3 +tries=1

# 2. Ask Google's resolver to identify itself.
dig @8.8.8.8 o-o.myaddr.l.google.com TXT +short
```

Measured on this network: test 1 timed out (no interception), and test 2
returned a genuine Google resolver address. Plain DNS queries here reach the
resolver they are addressed to, unmodified.

**What that means for this tool.** DNS on this connection is not currently
being tampered with, so DoH is defence-in-depth rather than a fix for an
active problem: it still encrypts your queries, removes the ISP's visibility
into which domains you resolve, and is in place the moment interference does
start. But if a specific game or site is failing *today*, re-run `diagnose`
against it — a `BlockedBeyondDns` verdict means the block is at the IP or SNI
level and no DNS change will help.

## Browsing and YouTube need no configuration

**This is settled — do not add a profile or domain list for YouTube or any
other site.** Once protection is on, the default policy sends *every* public
name over DoH. Profiles are an override mechanism, not a prerequisite.

Verified empirically, not assumed. With `profile=None` and `forced_domains=[]`:

| Route | Domain | Result |
|---|---|---|
| `doh` | `youtube.com` | `142.250.206.14` |
| `doh` | `www.youtube.com` | `142.251.154.4` |
| `doh` | `googlevideo.com` | `172.217.24.196` |
| `doh` | `i.ytimg.com` | `74.125.130.119` |
| `doh` | `yt3.ggpht.com` | `172.253.134.132` |
| `system` | `nas.lan` | forwarded to the LAN resolver |

The last row is the control: the policy discriminates rather than labelling
everything DoH. `policy::tests::ordinary_browsing_needs_no_configuration`
locks this in as a regression test, so a future change to the default policy
that quietly pushes browsing back onto the ISP path fails the suite.

Reproduce it yourself without touching system DNS:

```bash
./target/debug/dns-helper --config <cfg> run --no-takeover \
  --status-path /tmp/status.json          # proxy on a high port, no root
dig @127.0.0.1 -p 15353 youtube.com +short
jq -r '.recent[] | "\(.route)\t\(.name)"' /tmp/status.json
```

## Profiles (optional)

`~/.config/detour/config.toml`. None ship by default and none are needed:
the default policy already sends every public name over DoH. A profile forces
specific domains over DoH (useful only if you set `default_doh = false`) and
can hold a one-click launch command.

Domain lists must come from traffic you have actually observed, never guesses —
a wrong entry silently sends traffic somewhere it should not go.

```toml
[[profiles]]
id = "some-game"
name = "Some Game"
domains = ["login.example.com", "*.cdn.example.net"]   # verified only
launch_command = "steam"
launch_args = ["-applaunch", "12345"]
```

## App tunnel

Routes only apps launched from the **App tunnel** page through WireGuard
(Cloudflare WARP via `wgcf`, or any imported config); the rest of the system
keeps its normal connection. Apps are listed in `config.toml`:

```toml
[[tunnel_apps]]
name = "Brave"
command = "brave"
```

Apps run in `detourtunnel.slice`; nftables marks that cgroup's packets and a
policy rule routes them via `detour0`. It fails closed, persists nothing, and
`App tunnel → Stop` or a reboot removes it all.

## Launching games

Steam forks and returns immediately, so there is no child process to wait on.
DNS protection is therefore tied to **the app**, not to the game's lifetime:
turn it on, play, turn it off. This also means it covers your browser, which a
per-process approach could not.

## Optional: nicer elevation prompt

```bash
sudo install -Dm644 packaging/dev.local.detour.policy \
  /usr/share/polkit-1/actions/dev.local.detour.policy
```

Gives a prompt that explains what is being changed, and caches authorisation
briefly so start and stop are not two separate prompts. Edit the `exec.path`
annotation to match where you installed `dns-helper`.
