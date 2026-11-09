# Wazuh for macOS

A native macOS app that runs the complete **Wazuh 4.14.10** SIEM/XDR platform on your Mac: the **Wazuh server (manager)**, the **Wazuh indexer**, and the **Wazuh dashboard**. You control everything from one window.

![Wazuh for macOS](docs/screenshot-dashboard.png)

> **Unofficial community packaging.** It runs the unmodified official Wazuh images from
> [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker) (tag `v4.14.10`).
> It is not affiliated with or endorsed by Wazuh, Inc. Wazuh is licensed under GPLv2, and so is this project.

## Why Docker?

The Wazuh manager only runs on Linux, and it can't be compiled for macOS. So this app does what the official single-node deployment does: it runs the three official components as Linux containers through Docker Desktop. On Apple silicon those containers run natively as arm64 images. None of Wazuh's features are removed or changed: rules, decoders, FIM, SCA, vulnerability detection, active response, the API, agent enrollment, and the whole dashboard work exactly as upstream.

## Features

| | |
|---|---|
| **Overview** | Start, stop, and restart the stack. Shows live container state and endpoint health for the manager, indexer, and dashboard. Shows access credentials. |
| **Dashboard** | The full official Wazuh dashboard inside the app, with downloads, file uploads, and session persistence. |
| **Deploy Agents** | Install commands for macOS, Linux (DEB/RPM), and Windows agents, pre-filled with this Mac's IP address. |
| **Logs** | Live logs for each container, plus the app's own activity log. |
| **Settings** | Stack folder, ports, and a full data reset. |
| **Menu bar** | Shield icon showing status, with quick start and stop. |

## Install

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and give it at least **6 GB of memory** (8 GB recommended).
2. Download `Wazuh-4.14.10-macOS-arm64.dmg` from [Releases](../../releases), open it, and drag **Wazuh** to Applications.
3. The app is ad-hoc signed, not notarized. On first launch, right-click it and choose **Open**, or run:
   ```bash
   xattr -dr com.apple.quarantine /Applications/Wazuh.app
   ```
4. Click **Start Wazuh**. On the first run the app generates TLS certificates with the official `wazuh-certs-generator` and pulls about 3 GB of images. That takes a few minutes.
5. Log in to the dashboard as `admin` / `SecretPassword`.

### Default credentials (upstream wazuh-docker defaults)

| Component | URL | User | Password |
|---|---|---|---|
| Dashboard | https://localhost | `admin` | `SecretPassword` |
| Wazuh API | https://localhost:55000 | `wazuh-wui` | `MyS3cr37P450r.*-` |
| Indexer | https://localhost:9200 | `admin` | `SecretPassword` |

Change these before exposing the stack to a network. Follow the [wazuh-docker password guide](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html#change-the-password-of-wazuh-users), editing the files in the stack folder.

## Ports

`443` dashboard · `1514/tcp` agent events · `1515/tcp` enrollment · `514/udp` syslog · `55000` Wazuh API · `9200` indexer

## Where things live

- Compose stack and config: `~/Library/Application Support/WazuhMac/stack`. Edit `config/wazuh_cluster/wazuh_manager.conf` (ossec.conf) and so on, then restart the service.
- Data (alerts, agents, indexes): Docker volumes in the `wazuh-mac` compose project.
- Command-line access works too:
  ```bash
  cd ~/Library/Application\ Support/WazuhMac/stack && docker compose -p wazuh-mac ps
  ```

## Build from source

Requires the Xcode Command Line Tools (Swift 5.9+) on an Apple silicon Mac.

```bash
./scripts/build_app.sh   # -> dist/Wazuh.app
./scripts/make_dmg.sh    # -> dist/Wazuh-4.14.10-macOS-arm64.dmg
```

The project is a Swift package (`Sources/WazuhMac`, SwiftUI + WebKit). The bundled stack lives in `Resources/stack` and is copied verbatim from `wazuh-docker/single-node` at `v4.14.10`.

## License

GPLv2. See [LICENSE](LICENSE). Wazuh © Wazuh, Inc.
