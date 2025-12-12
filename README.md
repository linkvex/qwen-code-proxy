## Qwen Code Proxy

Cloudflare Worker that proxies requests to the Qwen Code API with automatic OAuth token refresh.

### Deploy to Cloudflare

You can deploy this worker directly to Cloudflare with one click:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/se7uh/qwen)

#### Prerequisites

1. Log in using the qwen-code CLI to generate your OAuth credentials.
2. Locate the credentials file:
   - Windows: `C:\Users\USERNAME\.qwen\oauth_creds.json`
   - macOS/Linux: `~/.qwen/oauth_creds.json`

#### Configuration

After clicking the Deploy button, you'll be prompted to configure:

- **QWEN_CREDS**: Required - Your Qwen OAuth credentials JSON
- **API_KEY**: Optional, but enabled by default - If you want to require authentication to use the proxy

### Local Development

If you prefer to run locally:

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Deploy to Cloudflare
npm run deploy
```
