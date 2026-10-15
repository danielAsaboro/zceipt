export interface Output { action: number; recipient: string; zatoshis: number; memo: string | null }
export interface Verification {
  object: "verification"; valid: true; livemode: boolean; network: "mainnet" | "testnet" | "regtest";
  pool: "orchard" | "ironwood" | "orchard_to_ironwood" | "ironwood_to_orchard"; txid: string; mined_height: number; message: string;
  challenge: string | null; batch: { id: string; position: number; total: number } | null;
  sender_addresses: string[]; outputs: Output[]; paid_to_expected?: number;
}
export interface BatchVerification {
  object: "batch_verification"; valid: true; livemode: boolean; id: string; total_zatoshis: number;
  totals_by_recipient: Record<string, number>; receipts: Verification[];
}
export interface ProofRequest {
  id: string; object: "proof_request"; livemode: boolean; status: "open" | "fulfilled" | "expired";
  kind: "single" | "partial" | "campaign"; received_zatoshis: number; remaining_zatoshis: number | null;
  payments: { txid: string; zatoshis: number; mined_height: number | null; memo: string | null }[];
  client_secret: string; hosted_url: string; public_url: string | null;
  challenge: string; payee: string; amount_zatoshis: number | null; label: string | null;
  metadata: Record<string, unknown>; created: number; expires_at: number | null;
  payment_uri: string; receipt_link: string; cli_command: string;
  fulfillment: null | { fulfilled_at: number; txid: string; paid_zatoshis: number; verification: Verification };
}
export interface Refund { id: string; object: "refund"; livemode: boolean; request: string; payment_txid: string; address: string; amount_zatoshis: number; reason: string | null; challenge: string; status: "pending" | "succeeded"; created: number; payment_uri: string; cli_command: string; refunded_at: number | null; txid: string | null }
export interface TestClock { id: string; object: "test_clock"; livemode: false; frozen_time: number; height: number; created: number; requests: string[] }
export interface SignInChallenge { id: string; object: "sign_in_challenge"; livemode: boolean; coin_type: number; domain: string; nonce: string; created: number; expires_at: number; status: "pending" | "used" | "expired"; wallet_command: string }
export interface SignInResult { object: "sign_in"; verified: true; livemode: boolean; challenge: string; domain: string; issued_at: number; address: string }
export interface WebhookEndpoint { id: string; object: "webhook_endpoint"; url: string; events: string[]; secret?: string }
export interface ReceiptsEvent<T = any> { id: string; object: "event"; type: "request.created" | "request.payment_received" | "request.fulfilled" | "request.expired" | "receipt.rejected"; created: number; livemode: boolean; data: { object: T } }
export interface List<T> { object: "list"; data: T[]; has_more: boolean }
export interface RequestOptions { idempotencyKey?: string }

export class ReceiptsError extends Error { status: number; type?: string; code?: string; param: string | null; docUrl?: string; raw: unknown }
export class AuthenticationError extends ReceiptsError {}
export class InvalidRequestError extends ReceiptsError {}
export class VerificationError extends ReceiptsError {}
export class ApiError extends ReceiptsError {}
export class ConnectionError extends ReceiptsError {}
export class WebhookSignatureError extends Error {}

export class Receipts {
  constructor(apiKey: string, options?: { baseUrl?: string; maxRetries?: number; timeoutMs?: number; fetch?: typeof fetch });
  readonly livemode: boolean;
  verify(params: string | { receipt: string; expect_address?: string; min_zatoshis?: number; challenge?: string }, opts?: RequestOptions): Promise<Verification | BatchVerification>;
  requests: {
    create(params: { payee: string; amount_zatoshis?: number; label?: string; metadata?: Record<string, unknown>; expires_in?: number; kind?: "single" | "partial" | "campaign"; test_clock?: string }, opts?: RequestOptions): Promise<ProofRequest>;
    retrieve(id: string): Promise<ProofRequest>;
    list(params?: { status?: "open" | "fulfilled" | "expired"; limit?: number; starting_after?: string }): Promise<List<ProofRequest>>;
    submitReceipt(id: string, params: { receipt: string }, opts?: RequestOptions): Promise<ProofRequest>;
    each(params?: { status?: "open" | "fulfilled" | "expired"; limit?: number }): AsyncIterable<ProofRequest>;
    qr(id: string): Promise<string>;
  };
  public: {
    getRequest(id: string, secret: string): Promise<any>;
    submitReceipt(id: string, params: { receipt: string; client_secret?: string }): Promise<any>;
    campaign(id: string): Promise<any>;
  };
  paymentLinks: { check(params: string | { uri: string; network?: "mainnet" | "testnet" | "regtest" }): Promise<any> };
  deliveries: { list(params?: { limit?: number }): Promise<List<any>> };
  sandbox: { fixtures(): Promise<List<string>> };
  errors: { list(): Promise<any> };
  health(): Promise<{ ok: boolean; version: string; test_network: string; live_network: string }>;
  refunds: {
    create(requestId: string, params?: { amount_zatoshis?: number; reason?: string; payment_txid?: string }, opts?: RequestOptions): Promise<Refund>;
    retrieve(id: string): Promise<Refund>;
    submitReceipt(id: string, params: { receipt: string }, opts?: RequestOptions): Promise<Refund>;
  };
  attestations: {
    create(requestId: string, params?: { at_least_zatoshis?: number; before?: string; disclose?: ("txid" | "amount_zatoshis" | "paid_at" | "request" | "label")[] }): Promise<{ object: "attestation"; request: string; claims: object; presentation: string; disclosures: Record<string, string>; jwks_url: string }>;
    verify(attestation: string): Promise<{ object: "attestation_verification"; valid: true; claims: object }>;
    jwks(): Promise<{ keys: object[] }>;
  };
  testClocks: {
    create(params?: { frozen_time?: number; height?: number }): Promise<TestClock>;
    retrieve(id: string): Promise<TestClock>;
    advance(id: string, params: { seconds?: number; blocks?: number }): Promise<TestClock & { fired: { type: string; request: string; event: string }[] }>;
    reorg(id: string, params?: { depth?: number }): Promise<TestClock & { fired: { type: string; request: string; event: string }[] }>;
  };
  signIn: {
    createChallenge(params?: { domain?: string }): Promise<SignInChallenge>;
    verify(params: string | { sign_in: string }): Promise<SignInResult>;
  };
  webhookEndpoints: {
    create(params: { url: string; events?: string[] }): Promise<WebhookEndpoint>;
    list(): Promise<List<WebhookEndpoint>>;
    del(id: string): Promise<{ id: string; deleted: true }>;
  };
  events: {
    list(params?: { limit?: number }): Promise<List<ReceiptsEvent>>;
    resend(id: string): Promise<ReceiptsEvent>;
  };
}

export const webhooks: {
  constructEvent<T = any>(rawBody: string | Uint8Array, signatureHeader: string | null | undefined, secret: string, options?: { toleranceSecs?: number }): Promise<ReceiptsEvent<T>>;
  sign(rawBody: string, secret: string, t?: number): Promise<string>;
};
