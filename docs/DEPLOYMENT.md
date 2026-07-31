# Deployment guide

## Docker

```bash
docker compose up --build
```

## systemd

Copy installer/usb-guard.service to /etc/systemd/system/usb-guard.service and enable it.

## Backup and restore

```bash
./installer/backup.sh
./installer/restore.sh
```
