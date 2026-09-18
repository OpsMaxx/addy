package services

// The restricted Docker socket.
//
// Every service here is a container, so something has to talk to Docker. The
// obvious way -- bind-mount /var/run/docker.sock -- is not a lesser privilege
// than root on the host, it IS root on the host: anything that can reach the
// Docker API can start a container with the host filesystem mounted and write
// to it as root. A relay whose pitch is that it holds nothing worth attacking
// should not casually hold that.
//
// So the compose fragment below puts a filtering proxy in front of the socket
// and grants the narrow set of calls a deployment actually needs. It is not a
// security boundary against a determined attacker who already has code
// execution here -- `POST /containers/create` is on the list, because installing
// a service means creating a container, and that call alone is enough to
// escape. What it buys is real and smaller: an exposure through one of these
// services reaches an API that cannot list every container on the box, cannot
// read another service's environment, cannot exec into anything and cannot
// reach the swarm or the plugin API.
//
// Saying that plainly matters more than the proxy does. A socket proxy
// described as "hardening" is one people trust to hold weight it cannot hold.

// SocketProxyCompose is the fragment `addy service install` writes once, the
// first time any service is installed.
const SocketProxyCompose = `# A filtering proxy in front of the Docker socket.
#
# WHAT THIS IS AND IS NOT
#
# It is not a boundary against code already running here: POST /containers/create
# is granted, because installing a service needs it, and that call is enough to
# mount the host filesystem. It narrows what an exposure in one of the services
# beside it can reach -- no exec, no listing other containers' environments, no
# swarm, no plugins -- and that is worth having without being what it is not.
#
# Every variable here defaults to 0. Adding one is a deliberate act.

services:
  docker-socket-proxy:
    image: lscr.io/linuxserver/socket-proxy:1.26.2
    container_name: addy-docker-proxy
    restart: unless-stopped
    environment:
      # What a deployment needs.
      CONTAINERS: "1"
      IMAGES: "1"
      NETWORKS: "1"
      VOLUMES: "1"
      POST: "1"
      # What it does not, spelled out rather than left to the image's defaults,
      # because a default that changes upstream changes this box silently.
      EXEC: "0"
      AUTH: "0"
      SECRETS: "0"
      CONFIGS: "0"
      SWARM: "0"
      NODES: "0"
      SERVICES: "0"
      TASKS: "0"
      PLUGINS: "0"
      SYSTEM: "0"
      INFO: "0"
      DISTRIBUTION: "0"
      SESSION: "0"
      BUILD: "0"
      COMMIT: "0"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      # Loopback only. A socket proxy reachable from the network is the socket
      # reachable from the network.
      - "127.0.0.1:2375:2375"
    read_only: true
    tmpfs:
      - /run
`

// ProxyDockerHost is what DOCKER_HOST becomes once the proxy is running.
const ProxyDockerHost = "tcp://127.0.0.1:2375"
