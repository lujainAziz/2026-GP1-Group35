# Avahi (mDNS) service advertisement

`assas-api.service` advertises the inventory API as `_assas._tcp` on port 8000 so
clients (the Flutter app) can discover the appliance by service type instead of a
hardcoded IP — important because the Pi's DHCP address changes per network.

Avahi already publishes the host record `assas-pi.local`; this file adds the API
service on top of it.

## Install on the Pi

```
sudo cp /home/assas/assas/appliance/avahi/assas-api.service /etc/avahi/services/assas-api.service
sudo systemctl reload avahi-daemon    # or: sudo systemctl restart avahi-daemon
```

## Verify

```
avahi-browse -rt _assas._tcp
```

Expect an entry resolving to `assas-pi.local`, the current IP, and port 8000.

## Remove

```
sudo rm /etc/avahi/services/assas-api.service
sudo systemctl reload avahi-daemon
```
