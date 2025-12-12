import { CredentialStore, ensureBaseUrl } from "./credentialStore";
import {
  Env,
  MissingCredentialsError,
  QwenCredentials,
  RefreshTokenError,
} from "./env";
import { createSSETransformer } from "./streamTransformer";

const AUTH_ERROR_STATUSES = new Set([401, 403]);
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Authorization,Content-Type",
  "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

function isRequestAuthorised(request: Request, env: Env): boolean {
  const requiredKey = env.API_KEY?.trim();
  if (!requiredKey) {
    return true;
  }

  const header = request.headers.get("Authorization");
  if (!header) {
    return false;
  }

  const [scheme, token] = header.split(/\s+/);
  if (!token || scheme.toLowerCase() !== "bearer") {
    return false;
  }

  return token === requiredKey;
}

function composeUpstreamUrl(
  baseUrl: string,
  path: string,
  search: string,
): string {
  const base = new URL(baseUrl);
  const basePath = base.pathname.replace(/\/$/, "");
  const targetPath = path.startsWith("/") ? path : `/${path}`;
  const combinedPath = `${basePath}${targetPath}`.replace(/\/\{2,}/g, "/");
  base.pathname = combinedPath || "/";
  base.search = search;
  return base.toString();
}

function withCors(
  response: Response,
  extraHeaders: HeadersInit = {},
): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    headers.set(key, value);
  }
  if (extraHeaders instanceof Headers) {
    extraHeaders.forEach((value, key) => headers.set(key, value));
  } else {
    for (const [key, value] of Object.entries(extraHeaders)) {
      if (typeof value === "string") {
        headers.set(key, value);
      }
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function jsonResponse(status: number, body: unknown): Response {
  const response = new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  });
  return withCors(response);
}

async function readBodyBuffer(request: Request): Promise<ArrayBuffer | null> {
  if (request.method === "GET" || request.method === "HEAD" || !request.body) {
    return null;
  }

  return await request.arrayBuffer();
}

function buildUpstreamRequest(
  original: Request,
  baseUrl: string,
  credentials: QwenCredentials,
  bodyBuffer: ArrayBuffer | null,
): Request {
  const incomingUrl = new URL(original.url);
  const upstreamUrl = composeUpstreamUrl(
    baseUrl,
    incomingUrl.pathname,
    incomingUrl.search,
  );
  const headers = new Headers(original.headers);

  headers.delete("Authorization");
  headers.delete("Host");
  headers.delete("Content-Length");
  headers.set(
    "Authorization",
    `${credentials.token_type} ${credentials.access_token}`,
  );

  const body =
    bodyBuffer && original.method !== "GET" && original.method !== "HEAD"
      ? bodyBuffer.slice(0)
      : undefined;

  return new Request(upstreamUrl, {
    method: original.method,
    headers,
    body,
    redirect: "manual",
  });
}

async function proxyOnce(
  originalRequest: Request,
  baseUrl: string,
  credentials: QwenCredentials,
  bodyBuffer: ArrayBuffer | null,
): Promise<Response> {
  const upstreamRequest = buildUpstreamRequest(
    originalRequest,
    baseUrl,
    credentials,
    bodyBuffer,
  );
  return fetch(upstreamRequest);
}

async function handleProxy(request: Request, env: Env): Promise<Response> {
  const credentialStore = new CredentialStore(env);
  const bodyBuffer = await readBodyBuffer(request);

  let credentials = await credentialStore.getValidCredentials();
  let baseUrl = ensureBaseUrl(credentials.resource_url);

  let response = await proxyOnce(request, baseUrl, credentials, bodyBuffer);

  if (AUTH_ERROR_STATUSES.has(response.status)) {
    try {
      credentials = await credentialStore.forceRefresh();
      baseUrl = ensureBaseUrl(credentials.resource_url);
      response = await proxyOnce(request, baseUrl, credentials, bodyBuffer);
    } catch (error) {
      console.error("Token refresh failed during proxy handling:", error);
      return jsonResponse(401, {
        error: "token_refresh_failed",
        message:
          error instanceof RefreshTokenError
            ? error.message
            : "Failed to refresh Qwen access token.",
      });
    }
  }

  const isStreaming = response.headers
    .get("content-type")
    ?.includes("text/event-stream");

  // For streaming responses (SSE), create a new response with proper streaming
  // This helps prevent stuttering by ensuring the stream is processed correctly through our transformer
  if (isStreaming && response.body) {
    // Create the transformer to process the SSE stream properly
    const transformer = createSSETransformer();
    const { readable, writable } = transformer;
    const writer = writable.getWriter();

    // Stream the original response through our transformer
    const reader = response.body.getReader();
    (async () => {
      let chunkCount = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunkCount++;
          if (value) {
            await writer.write(value);
          }
        }
      } catch (error) {
        console.error("Stream processing error:", error);
      } finally {
        reader.releaseLock();
        await writer.close();
      }
    })();

    // Create new response with properly handled stream and CORS headers
    const responseHeaders = new Headers(response.headers);
    // Add CORS headers to the streaming response
    for (const [key, value] of Object.entries(CORS_HEADERS)) {
      responseHeaders.set(key, value);
    }
    const newResponse = new Response(readable, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });

    return newResponse;
  }

  return withCors(response);
}

function handleOptions(): Response {
  return withCors(
    new Response(null, {
      status: 204,
    }),
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      if (request.method === "OPTIONS") {
        return handleOptions();
      }

      const url = new URL(request.url);

      if (!isRequestAuthorised(request, env)) {
        return jsonResponse(401, {
          error: "unauthorized",
          message: "Missing or invalid API key.",
        });
      }

      if (url.pathname === "/v1/models") {
        return jsonResponse(200, {
          object: "list",
          data: [
            {
              id: "coder-model",
              object: "model",
              created: Math.floor(Date.now() / 1000),
              owned_by: "user",
            },
            {
              id: "vision-model",
              object: "model",
              created: Math.floor(Date.now() / 1000),
              owned_by: "user",
            },
          ],
        });
      }

      return await handleProxy(request, env);
    } catch (error) {
      console.error("Unexpected error while processing request:", error);

      if (error instanceof MissingCredentialsError) {
        return jsonResponse(503, {
          error: "credentials_missing",
          message:
            "No oauth_creds.json found. Set the QWEN_CREDS_JSON secret (or seed KV manually) before using the proxy.",
        });
      }

      if (error instanceof RefreshTokenError) {
        return jsonResponse(error.status === 400 ? 401 : 502, {
          error: "refresh_failed",
          message: error.message,
        });
      }

      return jsonResponse(500, {
        error: "internal_error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  },
};
