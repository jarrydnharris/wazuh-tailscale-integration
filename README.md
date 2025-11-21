# Tailscale Security Monitoring Pipeline

Automated log collection and SIEM integration for Tailscale networks.

## Architecture
```
Tailscale → Log Collector → GitHub → Wazuh SIEM → Alerts
```

## Components

- **Log Collector**: Python script that extracts Tailscale logs
- **GitHub Actions**: Automated collection every hour
- **Wazuh Integration**: Security monitoring and alerting

## Setup Status

- [x] Repository created
- [x] Log collector script added
- [ ] GitHub Actions configured
- [ ] Wazuh integration deployed
- [ ] Custom rules added

## Quick Start

1. Install Tailscale
2. Run collector: `python3 scripts/collect_tailscale_logs.py logs/`
3. Check logs: `ls logs/`

## Documentation

- [Architecture](docs/architecture.md) - Coming soon
- [Setup Guide](docs/setup.md) - Coming soon
- [Troubleshooting](docs/troubleshooting.md) - Coming soon
