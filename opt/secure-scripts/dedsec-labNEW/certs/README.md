# TLS certs

Generate your own, e.g.:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 3650 \
  -subj "/CN=YOUR_LAB_HOST"
```

Point the lab API and the client `assets/lab_ca.pem` at your CA / cert as documented in the app TLS module.
