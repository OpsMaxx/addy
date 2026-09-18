package services

import (
	"errors"
	"fmt"
	"strings"
)

// The five wizards.
//
// Each one states its cost in the words an operator needs at the moment they
// decide, not afterwards. None of them is a recommendation.

func frp() Service {
	return Service{
		ID:      "frp",
		Name:    "frp (reverse tunnels)",
		Summary: "Expose a service on a private network through this box, over a tunnel it opens outward.",
		Cost: "This box becomes a public entry point for whatever you tunnel through it. " +
			"A tunnel is a hole you opened deliberately, and it stays open while frpc runs on the far side -- " +
			"including when the far side is a laptop somebody took to a cafe.",
		Fields: []Field{
			{
				Key: "FRP_TOKEN", Label: "Shared token", Kind: FieldSecret, Required: true,
				Help: "Every frpc that connects presents this. Anyone holding it can publish a tunnel through your box.",
			},
			{
				Key: "FRP_WILDCARD", Label: "Use a wildcard certificate", Kind: FieldBool, Default: "false",
				Help: "Gives every tunnel its own subdomain automatically. Needs DNS-01, which needs an API " +
					"credential for your DNS provider. Without it you name each subdomain up front.",
			},
			{
				Key: "FRP_DNS_PROVIDER", Label: "DNS provider", Kind: FieldChoice,
				Choices: []string{"cloudflare", "route53", "digitalocean", "gandi", "hetzner"},
				Help:    "Only with a wildcard certificate.",
			},
			{
				Key: "FRP_DNS_TOKEN", Label: "DNS API token", Kind: FieldSecret,
				Help: "Scoped to editing TXT records on this zone if your provider allows it. " +
					"A full-access token here is a full-access token on this box.",
			},
			{
				Key: "FRP_SUBDOMAINS", Label: "Subdomains", Kind: FieldText,
				Help: "Comma-separated, without a wildcard certificate. Each gets its own HTTP-01 certificate.",
			},
		},
		Prereqs: []Prereq{
			requireValue("FRP_TOKEN", "A shared token is set",
				"frp with no token accepts a tunnel from anyone who finds the port, which makes your box "+
					"an open proxy. Generate one: `openssl rand -hex 32`."),
			{
				// THE ONE THAT CANNOT BE WORKED AROUND, and the reason this
				// wizard asks for DNS credentials up front rather than
				// discovering the problem at first renewal.
				//
				// Let's Encrypt will not issue a wildcard over HTTP-01. Not
				// "does not by default" -- will not, ever, by design: the
				// challenge proves control of one name and a wildcard claims
				// all of them. A deployment that assumed otherwise works
				// perfectly until the certificate is requested and then fails
				// in a way that looks like a DNS problem.
				Name:  "A wildcard certificate has a DNS credential to use",
				Fatal: true,
				Check: func(cfg Config) error {
					if cfg.value("FRP_WILDCARD") != "true" {
						if cfg.value("FRP_SUBDOMAINS") == "" {
							return errors.New(
								"without a wildcard you have to name the subdomains up front, because each one " +
									"needs its own HTTP-01 certificate. List them, or turn the wildcard on and " +
									"supply a DNS API token.")
						}
						return nil
					}
					if cfg.value("FRP_DNS_PROVIDER") == "" || cfg.value("FRP_DNS_TOKEN") == "" {
						return errors.New(
							"a wildcard certificate can only be issued over DNS-01, and Let's Encrypt will not " +
								"issue one over HTTP-01 -- not by default, ever. Choose your DNS provider and " +
								"supply an API token, or turn the wildcard off and name the subdomains instead.")
					}
					return nil
				},
			},
		},
		Template: "frp.yml",
		// 7000 is frps's control port. The vhost ports are NOT here: frp's
		// HTTPS vhost is SNI passthrough through addy's front door, which is
		// the whole reason the four-way collision on 443 does not happen.
		Ports: []int{7000},
	}
}

func headscale() Service {
	return Service{
		ID:      "headscale",
		Name:    "headscale (Tailscale control plane)",
		Summary: "Run your own coordination server, so your machines form a mesh without a third party.",
		Cost: "The control plane decides which machines are in your network and issues the keys that let " +
			"them in. Compromising this box becomes compromising the membership of your whole mesh -- " +
			"not the traffic, which stays end-to-end encrypted, but who is on it.",
		Fields: []Field{
			{
				Key: "HEADSCALE_DERP", Label: "Run a DERP relay too", Kind: FieldBool, Default: "false",
				Help: "Relays traffic for machines that cannot reach each other directly. OFF by default: " +
					"it is bandwidth, it is a second public surface, and Tailscale's own relays work " +
					"without it unless you have a reason they must not.",
			},
			{
				Key: "HEADSCALE_PREFIX", Label: "IP range", Kind: FieldText, Default: "100.64.0.0/10",
				Help: "The addresses handed to machines. The default is the carrier-grade NAT range, " +
					"which is what Tailscale uses and is unlikely to collide with anything you own.",
			},
		},
		Prereqs: []Prereq{
			{
				Name:  "The IP range does not collide with this box's own networks",
				Fatal: false,
				Check: func(cfg Config) error {
					prefix := cfg.value("HEADSCALE_PREFIX")
					// A warning rather than a refusal: the operator may know
					// something we do not about their routing, and a wizard
					// that refuses a legal configuration is a wizard people
					// route around.
					if prefix != "" && !strings.HasPrefix(prefix, "100.64.") {
						return fmt.Errorf(
							"%s is not the usual 100.64.0.0/10. That is allowed, and it is worth checking it "+
								"does not overlap a network your machines are already on -- an overlap shows up "+
								"as one host being unreachable from one other, months later", prefix)
					}
					return nil
				},
			},
		},
		Template: "headscale.yml",
		// 8080 is headscale's own HTTP, loopback only -- addy's front door
		// terminates TLS and proxies to it. 3478 is DERP's STUN, and only when
		// DERP is on, which is why it is not in this list: a port check that
		// refused 3478 would collide with addy's own TURN relay for every
		// operator who never turned DERP on.
		Ports: []int{8080},
	}
}

func wireguard() Service {
	return Service{
		ID:      "wireguard",
		Name:    "WireGuard",
		Summary: "A plain WireGuard server, for clients that will not run anything else.",
		Cost: "A private key on this box is the key to your network. WireGuard has no revocation: " +
			"removing a peer means editing the config and reloading, and a peer you forget to remove " +
			"is a peer that still works.",
		Fields: []Field{
			{
				Key: "WG_PORT", Label: "UDP port", Kind: FieldText, Default: "51820",
				Help: "51820 is the convention. addy's TURN relay is deliberately configured to " +
					"allocate above it, so the two cannot collide.",
			},
			{
				Key: "WG_SUBNET", Label: "Client subnet", Kind: FieldText, Default: "10.13.13.0/24",
			},
		},
		Prereqs: []Prereq{
			{
				Name:  "The kernel has WireGuard",
				Fatal: false,
				Check: func(Config) error {
					// A warning: the container falls back to a userspace
					// implementation, which works and is slower. Refusing
					// would stop a perfectly serviceable deployment on a VPS
					// with an old kernel.
					return errors.New(
						"not checked from inside addy -- `modprobe wireguard` on the host answers it. " +
							"Without the module the container falls back to userspace, which works and is " +
							"noticeably slower under load")
				},
			},
		},
		Template: "wireguard.yml",
		Ports:    []int{51820},
	}
}

func openvpn() Service {
	return Service{
		ID:      "openvpn",
		Name:    "OpenVPN",
		Summary: "For clients and networks that have OpenVPN and will not have anything else.",
		Cost: "A certificate authority lives on this box. Whoever holds the CA key can mint a client " +
			"certificate for your network at any time, and nothing about that is visible from the " +
			"outside. It is the single most valuable thing addy will ever be asked to store.",
		Fields: []Field{
			{Key: "OVPN_PORT", Label: "UDP port", Kind: FieldText, Default: "1194"},
			{
				Key: "OVPN_CN", Label: "CA common name", Kind: FieldText, Required: true,
				Help: "Appears in every certificate this CA issues. Your organisation or hostname.",
			},
		},
		Prereqs: []Prereq{
			requireValue("OVPN_CN", "The CA has a name",
				"Every certificate this CA issues carries it, and changing it later means reissuing all of them."),
			{
				Name:  "You have somewhere to keep the CA key that is not this box",
				Fatal: false,
				Check: func(Config) error {
					// Not checkable, and said anyway. A prerequisite that
					// cannot be verified is still worth stating when the cost
					// of not thinking about it is total: this is the one
					// service here whose compromise cannot be undone by
					// rotating a token.
					return errors.New(
						"nothing can check this for you. `addy panic` rotates what it can and cannot un-issue " +
							"a certificate somebody already took -- plan for where the CA key is backed up, and " +
							"for how you would revoke, before you have to")
				},
			},
		},
		Template: "openvpn.yml",
		Ports:    []int{1194},
	}
}

func vaultwarden() Service {
	return Service{
		ID:      "vaultwarden",
		Name:    "Vaultwarden (Bitwarden-compatible)",
		Summary: "A password manager for the Bitwarden clients, on your own box.",
		Cost: "THIS IS THE ONE TO THINK HARDEST ABOUT. addy's pitch is a relay that holds nothing worth " +
			"attacking; Vaultwarden is a password database. Running them together means a single " +
			"compromise reaches both, and it changes what your relay is for. The vaults are encrypted " +
			"to their users' master passwords -- but an attacker on this box can serve modified " +
			"JavaScript to the web vault, and then they are not attacking encryption at all. " +
			"Run it on a different box unless you have a reason not to.",
		Fields: []Field{
			{
				Key: "VW_ADMIN_TOKEN", Label: "Admin token", Kind: FieldSecret,
				Help: "Leave blank to disable the admin page entirely, which is the better answer unless " +
					"you need it today.",
			},
			{
				Key: "VW_SIGNUPS", Label: "Allow new signups", Kind: FieldBool, Default: "false",
				Help: "Off. An open signup page on a public host is an invitation.",
			},
		},
		Prereqs: []Prereq{
			{
				Name:  "This box is not also acting as your relay",
				Fatal: false,
				Check: func(cfg Config) error {
					// A warning rather than a refusal, deliberately: the
					// operator may be perfectly clear about the trade and
					// running a personal box where it is obviously fine. What
					// is not acceptable is them not noticing.
					return errors.New(
						"addy is a relay, and this box is running it. Co-locating a password database with " +
							"the thing whose whole design is that it holds no secrets means one compromise " +
							"reaches both. That can be the right call for a personal box; it should be a call")
				},
			},
		},
		Template: "vaultwarden.yml",
		// Loopback only: addy's front door terminates TLS and proxies to it,
		// which is what keeps Vaultwarden off the public interface.
		Ports: []int{8222},
	}
}
