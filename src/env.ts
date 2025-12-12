export interface QwenCredentials {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expiry_date: number;
  resource_url?: string;
}

export interface TokenRefreshResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string | null;
  resource_url?: string | null;
  status?: string;
  scope?: string;
}

export interface ErrorData {
  error: string;
  error_description?: string;
}

export interface Env {
  QWEN_CODE_KV: KVNamespace;
  QWEN_CREDS?: string;
  API_KEY?: string;
}

export class MissingCredentialsError extends Error {
  constructor(
    message = "Qwen OAuth credentials are not initialised. Configure the QWEN_CREDS secret or seed the KV namespace.",
  ) {
    super(message);
    this.name = "MissingCredentialsError";
  }
}

export class RefreshTokenError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "RefreshTokenError";
  }
}
