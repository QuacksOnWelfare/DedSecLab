# OVH DDoS -> Discord alerts

A small OVH Game DDoS alert bridge that posts to Discord.
Supply your own credentials and account-specific IDs in config.json.

## What to fill in

Copy `config.example.json` to `config.json` and set:

- `ovh_app_key` / `ovh_app_secret` / `ovh_consumer_key` - from the OVH API console
- `ovh_endpoint` - e.g. `ovh-eu`
- `discord_webhook_url` - your Discord webhook
- `service_name` - your OVH IP / service id

Then run `ovh_ddos_discord.py` (owner misc tools can call the same pattern).
