# Hosting notes

Quant Terminal currently runs as a local, single-user app. It is not ready to serve anonymous visitors from a public URL.

Before connecting it to a public website or a Hetzner server:

- Isolate saved state, alerts, and paper portfolios per user, or disable those writes in guest mode. The current JSON store is shared by the whole server process.
- Restrict the API routes that read or write state. They currently have no user authentication.
- Remove or protect custom-indicator uploads. The server writes submitted JavaScript to disk and imports it.
- Restrict the webhook tester. It makes server-side requests to a URL supplied by the caller.
- Disable the local PTQ bridge in guest mode, or limit it to a trusted authenticated operator. It assumes the PTQ service is running on the same computer.
- Keep Node bound to `127.0.0.1` behind a TLS reverse proxy. Do not expose the app's Node port directly.
- Add request limits, rate limits, and caching for market-data endpoints before inviting public traffic.

For a first public version, prefer a read-only guest mode with browser-local preferences. Keep alerts, webhook tests, custom code uploads, and the PTQ bridge available only in a trusted local or authenticated deployment.
