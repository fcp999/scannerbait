# Scannerbait

A small Flask honeypot for web scanners. It listens on port 80 in the container (port 8080 by default with Compose) and serves synthetic, inert decoy data for common exposure probes.

## What it answers

It recognizes probes seen in the attached session sample, including `/robots.txt`, `.env` variants, AWS/GCP/Azure credential paths, `.git/config`, SSH key paths, `/etc/passwd`, Terraform and Compose files, and VPN profiles such as Zscaler, Tailscale, ZeroTier, Xray, WireGuard, and OpenVPN. Recognized paths return fabricated data; unknown paths get a 404. The server never reads requested paths from disk.

Every fake credential is marked `DECOY_ONLY`, uses the reserved `.invalid` domain or documentation-only IP ranges, and is not usable. Login attempts are recorded without saving passwords. Logs are JSON lines on stdout, with control characters escaped so a request cannot inject terminal controls or extra log records. This also works with the Compose container's read-only root filesystem.

## Run

```sh
docker compose up -d --build
docker compose logs -f scannerbait
```

## Terminal-control decoy

`/decoy/terminal.txt` returns sample log lines with commas and quotes plus bell/ANSI sequences. By default, the sequences are literal text (`\x07`, `\x1b...`) and cannot ring a bell or recolor a terminal. To return actual BEL and ANSI bytes, explicitly set `SCANNERBAIT_RAW_CONTROLS=1` in the container environment and recreate it:

```sh
docker compose up -d --force-recreate
```

Raw mode is off by default because terminal control bytes can disrupt or obscure downstream logs. Only enable it on a honeypot you control and when intentionally testing a scanner or logger. The route is a response body only; controls are never placed in HTTP headers or this server's own logs.

## Configure

- `PORT`: listener port inside the container; default `80`.
- `SCANNERBAIT_RAW_CONTROLS`: `0` by default; set to `1` to return real terminal control bytes from the dedicated decoy route.
