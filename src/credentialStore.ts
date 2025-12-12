import {
  Env,
  MissingCredentialsError,
  QwenCredentials,
  RefreshTokenError,
  TokenRefreshResponse,
  ErrorData,
} from "./env";

const CREDENTIALS_KEY = "oauth_creds.json";
const REFRESH_BUFFER_MS = 30_000;
const DEFAULT_CLIENT_ID = "f0304373b74a44d2b584a3fb70ca9e56";
const DEFAULT_TOKEN_ENDPOINT = "https://chat.qwen.ai/api/v1/oauth2/token";
const DEFAULT_RESOURCE_URL = "portal.qwen.ai";
const REFRESH_MAX_RETRIES = 3;
const REFRESH_RETRY_DELAY_MS = 500;
const RETRYABLE_REFRESH_STATUSES = new Set([
  500, 502, 503, 504, 520, 521, 522, 523, 524,
]);

let refreshPromise: Promise<QwenCredentials> | null = null;
let refreshLockKey: string | null = null;
let refreshLockTimeout: number = 10000;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function generateLockKey(): string {
  return `lock_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function isErrorResponse(
  response: TokenRefreshResponse | ErrorData,
): response is ErrorData {
  return "error" in response;
}

function parseCredentials(raw: string | null): QwenCredentials {
  if (!raw) {
    throw new MissingCredentialsError();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new MissingCredentialsError(
      `Unable to parse oauth_creds.json provided via KV/QWEN_CREDS: ${(error as Error).message}`,
    );
  }

  const candidate = parsed as Partial<QwenCredentials>;
  if (
    !candidate ||
    typeof candidate.access_token !== "string" ||
    typeof candidate.refresh_token !== "string" ||
    typeof candidate.token_type !== "string" ||
    typeof candidate.expiry_date !== "number"
  ) {
    throw new MissingCredentialsError(
      "Stored oauth_creds.json is missing required fields (access_token, refresh_token, token_type, expiry_date).",
    );
  }

  return {
    access_token: candidate.access_token,
    refresh_token: candidate.refresh_token,
    token_type: candidate.token_type,
    expiry_date: candidate.expiry_date,
    resource_url: candidate.resource_url,
  };
}

export class CredentialStore {
  private cache: QwenCredentials | null = null;
  private cacheTimestamp: number | null = null;

  constructor(private readonly env: Env) {}

  private get clientId(): string {
    return DEFAULT_CLIENT_ID.trim();
  }

  private get tokenEndpoint(): string {
    return DEFAULT_TOKEN_ENDPOINT.trim();
  }

  private get defaultResourceUrl(): string {
    return DEFAULT_RESOURCE_URL.trim();
  }

  private lastCheck: number = 0;
  private checkPromise: Promise<void> | null = null;
  private readonly cacheCheckInterval: number = 5000;

  private async checkAndReloadIfNeeded(): Promise<void> {
    // If there's already an ongoing check, wait for it to complete
    if (this.checkPromise) {
      await this.checkPromise;
      return;
    }

    // If there's an ongoing refresh, skip the file check as refresh will handle it
    if (refreshPromise) {
      return;
    }

    const now = Date.now();

    // Limit check frequency to avoid excessive KV reads
    if (now - this.lastCheck < this.cacheCheckInterval) {
      return;
    }

    // Start the check operation and store the promise
    this.checkPromise = this.performFileCheck(now);

    try {
      await this.checkPromise;
    } finally {
      this.checkPromise = null;
    }
  }

  private async performFileCheck(checkTime: number): Promise<void> {
    this.lastCheck = checkTime;

    try {
      const versionKey = `${CREDENTIALS_KEY}.version`;
      const currentVersion = await this.env.QWEN_CODE_KV.get(versionKey, "text");
      const cachedVersion = this.cache?.access_token?.substring(0, 8);

      if (currentVersion && currentVersion !== cachedVersion) {
        await this.reloadCredentialsFromKV();
      }
    } catch (error) {
      if (
        error instanceof Error &&
        "status" in error &&
        (error as any).status !== 404
      ) {
        console.warn(`Failed to access credentials KV: ${error.message}`);
      }
    }
  }

  private async reloadCredentialsFromKV(): Promise<void> {
    try {
      const raw = await this.env.QWEN_CODE_KV.get(CREDENTIALS_KEY, {
        type: "text",
      });
      if (!raw) {
        this.cache = null;
        this.cacheTimestamp = 0;
        return;
      }

      const parsedData = JSON.parse(raw);
      const credentials = parseCredentials(raw);
      const normalised: QwenCredentials = {
        ...credentials,
        resource_url: this.normaliseResourceUrl(credentials.resource_url),
      };

      // Update memory cache
      this.cache = normalised;
      this.cacheTimestamp = Date.now();
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes("Invalid credentials")
      ) {
        console.warn(`Failed to validate credentials: ${error.message}`);
      }
      this.cache = null;
    }
  }

  private async read(): Promise<QwenCredentials> {
    await this.checkAndReloadIfNeeded();

    if (this.cache && this.cacheTimestamp) {
      return this.cache;
    }

    const raw = await this.env.QWEN_CODE_KV.get(CREDENTIALS_KEY, {
      type: "text",
    });

    if (!raw) {
      const seeded = this.env.QWEN_CREDS?.trim();
      if (seeded) {
        const credentialsFromSecret = parseCredentials(seeded);
        const normalisedFromSecret: QwenCredentials = {
          ...credentialsFromSecret,
          resource_url: this.normaliseResourceUrl(
            credentialsFromSecret.resource_url,
          ),
        };
        await this.write(normalisedFromSecret);
        this.cache = normalisedFromSecret;
        this.cacheTimestamp = Date.now();
        return normalisedFromSecret;
      }
      throw new MissingCredentialsError();
    }

    const credentials = parseCredentials(raw);
    const normalised: QwenCredentials = {
      ...credentials,
      resource_url: this.normaliseResourceUrl(credentials.resource_url),
    };

    this.cache = normalised;
    this.cacheTimestamp = Date.now();
    return normalised;
  }

  private async write(credentials: QwenCredentials): Promise<void> {
    this.cache = credentials;
    this.cacheTimestamp = Date.now();

    // Store the credentials
    await this.env.QWEN_CODE_KV.put(CREDENTIALS_KEY, JSON.stringify(credentials));

    const versionKey = `${CREDENTIALS_KEY}.version`;
    const version = credentials.access_token.substring(0, 8);
    await this.env.QWEN_CODE_KV.put(versionKey, version);
  }

  private async clear(): Promise<void> {
    this.cache = null;
          await this.env.QWEN_CODE_KV.delete(CREDENTIALS_KEY);

    // clear the version key
    const versionKey = `${CREDENTIALS_KEY}.version`;
    await this.env.QWEN_CODE_KV.delete(versionKey);
  }

  private needsRefresh(credentials: QwenCredentials): boolean {
    const now = Date.now();
    return (
      !credentials.expiry_date ||
      now + REFRESH_BUFFER_MS >= credentials.expiry_date
    );
  }

  private buildRequestBody(refreshToken: string): string {
    const params = new URLSearchParams();
    params.set("grant_type", "refresh_token");
    params.set("refresh_token", refreshToken);
    params.set("client_id", this.clientId);
    return params.toString();
  }

  private normaliseResourceUrl(resourceUrl?: string | null): string {
    const base =
      resourceUrl && resourceUrl.trim().length > 0
        ? resourceUrl.trim()
        : this.defaultResourceUrl;
    return base.replace(/^https?:\/\//, "");
  }

  private async performRefresh(
    current: QwenCredentials,
  ): Promise<QwenCredentials> {
    console.log(
      `Starting token refresh process. Current token expires at: ${new Date(current.expiry_date).toISOString()}`,
    );

    if (!current.refresh_token) {
      console.error(
        "No refresh token available for oauth_creds.json. Re-authentication is required.",
      );
      throw new RefreshTokenError(
        "No refresh token available for oauth_creds.json. Re-authentication is required.",
      );
    }

    const body = this.buildRequestBody(current.refresh_token);
    let lastError: RefreshTokenError | null = null;

    for (let attempt = 0; attempt < REFRESH_MAX_RETRIES; attempt++) {
      console.log(
        `Token refresh attempt ${attempt + 1}/${REFRESH_MAX_RETRIES}`,
      );

      try {
        const response = await fetch(this.tokenEndpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/json",
            "x-request-id": crypto.randomUUID(),
          },
          body,
        });

        if (!response.ok) {
          const responseText = await response.text();
          console.warn(
            `Token refresh failed with status ${response.status}: ${responseText}`,
          );

          if (response.status === 400) {
            console.error(
              "Refresh token rejected by Qwen. Clearing credentials.",
            );
            await this.clear();
            throw new RefreshTokenError(
          "Refresh token rejected by Qwen. Update the QWEN_CREDS secret using 'npx wrangler secret put QWEN_CREDS'.",
          response.status,
        );
          }

          const cfRay = response.headers.get("cf-ray");
          const upstreamRequestId = response.headers.get("x-request-id");
          const debugInfo = [
            cfRay ? `cf-ray: ${cfRay}` : null,
            upstreamRequestId ? `x-request-id: ${upstreamRequestId}` : null,
          ]
            .filter((value): value is string => Boolean(value))
            .join(", ");

          const messageBase = responseText
            ? `Token refresh failed with status ${response.status}: ${responseText}`
            : `Token refresh failed with status ${response.status}: ${response.statusText}`;
          const detailedMessage = debugInfo
            ? `${messageBase} (${debugInfo})`
            : messageBase;

          if (
            RETRYABLE_REFRESH_STATUSES.has(response.status) &&
            attempt < REFRESH_MAX_RETRIES - 1
          ) {
            console.warn(
              `Token refresh received ${response.status}. Retrying (${attempt + 1}/${REFRESH_MAX_RETRIES})…`,
            );
            await delay(REFRESH_RETRY_DELAY_MS * 2 ** attempt);
            continue;
          }

          throw new RefreshTokenError(detailedMessage, response.status);
        }

        let data: TokenRefreshResponse | ErrorData;
        try {
          data = (await response.json()) as TokenRefreshResponse | ErrorData;
        } catch (error) {
          console.error(
            `Token refresh response was not valid JSON: ${(error as Error).message}`,
          );
          throw new RefreshTokenError(
            `Token refresh response was not valid JSON: ${(error as Error).message}`,
          );
        }

        // Check if the response body contains an error (even with HTTP 200)
        if (isErrorResponse(data)) {
          const errorData = data as ErrorData;
          console.error(
            `Token refresh failed with error: ${errorData.error} - ${errorData.error_description || ""}`,
          );
          await this.clear();
          throw new RefreshTokenError(
            `Token refresh failed: ${errorData.error || "Unknown error"}${
              errorData.error_description
                ? ` - ${errorData.error_description}`
                : ""
            }`,
            400,
          );
        }

        // Now we know it's a successful TokenRefreshResponse
        const tokenData = data as TokenRefreshResponse;
        if (
          !tokenData.access_token ||
          !tokenData.token_type ||
          typeof tokenData.expires_in !== "number"
        ) {
          console.error("Token refresh response was missing required fields");
          throw new RefreshTokenError(
            "Token refresh response was missing access_token, token_type, or expires_in.",
          );
        }

        const refreshed: QwenCredentials = {
          access_token: tokenData.access_token,
          token_type: tokenData.token_type,
          refresh_token: tokenData.refresh_token || current.refresh_token,
          expiry_date: Date.now() + tokenData.expires_in * 1000,
          resource_url: this.normaliseResourceUrl(
            tokenData.resource_url ?? current.resource_url,
          ),
        };

        console.log(
          `Token refresh successful. New token expires at: ${new Date(refreshed.expiry_date).toISOString()}`,
        );
        await this.write(refreshed);
        return refreshed;
      } catch (error) {
        console.error(`Token refresh attempt ${attempt + 1} failed:`, error);

        if (error instanceof RefreshTokenError) {
          lastError = error;
        } else {
          lastError = new RefreshTokenError(
            `Token refresh request failed: ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
        }

        if (attempt < REFRESH_MAX_RETRIES - 1) {
          console.warn(
            `Token refresh attempt ${attempt + 1} failed: ${lastError.message}. Retrying in ${REFRESH_RETRY_DELAY_MS * 2 ** attempt}ms…`,
          );
          await delay(REFRESH_RETRY_DELAY_MS * 2 ** attempt);
          continue;
        }

        console.error("Token refresh failed after all retries");
        throw lastError;
      }
    }

    console.error("Token refresh failed after all attempts");
    throw (
      lastError ??
      new RefreshTokenError("Token refresh failed after multiple attempts.")
    );
  }

  private async acquireDistributedLock(): Promise<string | null> {
    const lockKey = generateLockKey();
    const maxAttempts = 20;
    const attemptInterval = 100;
    const maxInterval = 2000;

    let currentInterval = attemptInterval;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        // First, try to get the current lock
        const existingLock = await this.env.QWEN_CODE_KV.get(
          "oauth_refresh_lock",
          "text",
        );

        if (existingLock) {
          // Check if the existing lock is stale (older than refreshLockTimeout)
          let lockData;
          try {
            lockData = JSON.parse(existingLock);
          } catch (parseError) {
            console.warn("Invalid lock data found, clearing it:", existingLock);
            await this.env.QWEN_CODE_KV.delete("oauth_refresh_lock");
            continue; // Retry immediately after clearing invalid lock
          }

          if (lockData && lockData.timestamp) {
            const lockAge = Date.now() - lockData.timestamp;

            // Remove stale locks that exceed timeout
            if (lockAge > refreshLockTimeout) {
              console.warn(`Found stale lock: ${lockAge}ms old, removing it`);
              await this.env.QWEN_CODE_KV.delete("oauth_refresh_lock");
              // Continue to try acquiring the lock after clearing stale lock
            } else {
              // Lock is still active, wait and retry
              await delay(currentInterval);
              currentInterval = Math.min(currentInterval * 1.5, maxInterval);
              continue;
            }
          }
        }

        // Now attempt to acquire the lock by putting our lock data
        const lockData = {
          key: lockKey,
          timestamp: Date.now(),
          value: `locked_${Date.now()}`,
        };

        // Put the lock with expiration
        await this.env.QWEN_CODE_KV.put(
          "oauth_refresh_lock",
          JSON.stringify(lockData),
          {
            expirationTtl: Math.max(60, Math.ceil(refreshLockTimeout / 1000)), // Convert to seconds, minimum 60 for Cloudflare
          },
        );

        // Verify we actually got the lock (in case of race condition)
        const verification = await this.env.QWEN_CODE_KV.get(
          "oauth_refresh_lock",
          "text",
        );
        let verificationData;
        try {
          verificationData = JSON.parse(verification || "{}");
        } catch (parseError) {
          console.error(
            "Failed to parse lock verification data:",
            verification,
          );
          return null;
        }

        if (verificationData.key === lockKey) {
          refreshLockKey = lockKey;
          console.log(
            "Successfully acquired distributed lock for token refresh",
          );
          return lockKey;
        } else {
          // Another worker got the lock in the meantime, wait and retry
          await delay(currentInterval);
          currentInterval = Math.min(currentInterval * 1.5, maxInterval);
          continue;
        }
      } catch (error) {
        console.error("Error acquiring distributed lock:", error);
        return null;
      }
    }

    console.error("Failed to acquire distributed lock after maximum attempts");
    return null;
  }

  private async releaseDistributedLock(lockKey: string): Promise<void> {
    try {
      const currentLock = await this.env.QWEN_CODE_KV.get(
        "oauth_refresh_lock",
        "text",
      );
      if (currentLock) {
        let lockData;
        try {
          lockData = JSON.parse(currentLock);
        } catch (parseError) {
          console.error(
            "Failed to parse existing lock data during release:",
            currentLock,
          );
          // Try to delete the lock anyway
          await this.env.QWEN_CODE_KV.delete("oauth_refresh_lock");
          return;
        }

        if (lockData.key === lockKey) {
          await this.env.QWEN_CODE_KV.delete("oauth_refresh_lock");
          console.log("Successfully released distributed lock");
        } else {
          console.warn(
            "Lock key mismatch during release, another process may have acquired it",
          );
        }
      } else {
        console.warn(
          "Lock not found during release, may have been released by timeout",
        );
      }
    } catch (error) {
      console.error("Error releasing distributed lock:", error);
    }
  }

  private async performTokenRefresh(
    forceRefresh = false,
  ): Promise<QwenCredentials> {
    // Acquire distributed lock
    const lockKey = await this.acquireDistributedLock();
    if (!lockKey) {
      // If we can't get the lock, wait a bit and then try to get the latest credentials
      // This means another worker is already refreshing, so we wait and return current valid credentials
      await delay(1000); // Wait 1 second before trying to read again
      const credentials = await this.read();
      return credentials;
    }

    try {
      // Check if credentials KV has been updated by other sessions (after acquiring lock)
      await this.checkAndReloadIfNeeded();

      // Use refreshed credentials if they're now valid (unless force refresh is requested)
      if (!forceRefresh && this.cache && !this.needsRefresh(this.cache)) {
        return this.cache;
      }

      // Perform the actual token refresh
      const currentCredentials = await this.read();
      const refreshedCredentials =
        await this.performRefresh(currentCredentials);

      // Update memory cache with refreshed credentials
      this.cache = refreshedCredentials;
      this.cacheTimestamp = Date.now();

      return refreshedCredentials;
    } finally {
      // Always release the lock
      if (refreshLockKey) {
        await this.releaseDistributedLock(refreshLockKey);
        refreshLockKey = null;
      }
    }
  }

  async getValidCredentials(forceRefresh = false): Promise<QwenCredentials> {
    try {
      // Check if credentials KV has been updated by other sessions
      await this.checkAndReloadIfNeeded();

      // Return valid cached credentials if available (unless force refresh is requested)
      if (
        !forceRefresh &&
        this.cache &&
        this.cacheTimestamp &&
        !this.needsRefresh(this.cache)
      ) {
        return this.cache;
      }

      // Use a local promise variable to avoid race conditions
      let currentRefreshPromise = refreshPromise;

      if (!currentRefreshPromise) {
        // Start new refresh operation with distributed locking
        currentRefreshPromise = this.performTokenRefresh(forceRefresh);
        refreshPromise = currentRefreshPromise;
      }

      try {
        const result = await currentRefreshPromise;
        if (result === null) {
          throw new RefreshTokenError(
            "Token refresh returned null credentials",
          );
        }
        return result;
      } finally {
        if (refreshPromise === currentRefreshPromise) {
          refreshPromise = null;
        }
      }
    } catch (error) {
      if (error instanceof RefreshTokenError) {
        throw error;
      }

      throw new RefreshTokenError(
        `Failed to get valid credentials: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async forceRefresh(): Promise<QwenCredentials> {
    return this.getValidCredentials(true);
  }
}

export function ensureBaseUrl(resourceHost: string | undefined): string {
  const host =
    resourceHost && resourceHost.trim().length > 0
      ? resourceHost.trim()
      : DEFAULT_RESOURCE_URL;
  const withScheme = host.startsWith("http") ? host : `https://${host}`;
  const parsed = new URL(withScheme);
  const normalisedPath = parsed.pathname.replace(/\/$/, "");
  return `${parsed.origin}${normalisedPath}` || parsed.origin;
}

export { CREDENTIALS_KEY };
