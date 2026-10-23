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

`/decoy/terminal.txt` returns sample log lines with commas and quotes plus real BEL/ANSI bytes by default. The eight BEL bytes may ring a bell, and `ESC[30;40m` makes enclosed text black on black until `ESC[0m` resets it. This is intentionally aimed at testing how scanners and loggers handle terminal controls.

To disable raw controls and return the visible strings `\x07` and `\x1b...` instead, set `SCANNERBAIT_RAW_CONTROLS=0` and recreate the container:

```sh
SCANNERBAIT_RAW_CONTROLS=0 docker compose up -d --force-recreate
```

The controls are confined to this route's response body. They are never placed in HTTP headers or Scannerbait's own logs.

## Configure

- `PORT`: listener port inside the container; default `80`.
- `SCANNERBAIT_RAW_CONTROLS`: `1` by default; set to `0` to return escaped visible text from the dedicated decoy route.
