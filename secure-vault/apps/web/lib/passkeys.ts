/**
 * Browser-side WebAuthn glue: converts between the JSON-safe base64url
 * encoding our API speaks and the ArrayBuffer-based DOM credential API, and
 * performs the ceremonies via `navigator.credentials`.
 *
 * Everything here talks to the *authenticator*; verification of the responses
 * happens server-side (crates/webauthn) — the browser is never trusted.
 */

function b64urlToBuffer(b64url: string): ArrayBuffer {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function bufferToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, Array.from(bytes.slice(i, i + 0x8000)) as number[]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function passkeysSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    !!window.PublicKeyCredential &&
    typeof navigator.credentials?.create === 'function'
  );
}

/** JSON-shaped creation options as delivered by our API (matches the DOM
 * `PublicKeyCredentialCreationOptionsJSON` shape loosely on purpose). */
interface CreationOptionsJSON {
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: string; alg: number }[];
  timeout?: number;
  attestation?: string;
  authenticatorSelection?: Record<string, unknown>;
  excludeCredentials?: { type?: string; id: string }[];
}

interface RequestOptionsJSON {
  challenge: string;
  rpId?: string;
  allowCredentials?: { type?: string; id: string }[];
  timeout?: number;
  userVerification?: string;
}

// Accept both our loose shape and the DOM lib's JSON variants.
export type CreationOptionsInput = CreationOptionsJSON | PublicKeyCredentialCreationOptionsJSON;
export type RequestOptionsInput = RequestOptionsJSON | PublicKeyCredentialRequestOptionsJSON;

/** Run `navigator.credentials.create()` and return API-ready base64url fields. */
export async function createPasskey(optionsJSON: CreationOptionsInput): Promise<{
  credential_id: string;
  attestation_object: string;
  client_data_json: string;
}> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: b64urlToBuffer(optionsJSON.challenge),
      rp: optionsJSON.rp,
      user: {
        ...optionsJSON.user,
        id: b64urlToBuffer(optionsJSON.user.id),
      },
      pubKeyCredParams: optionsJSON.pubKeyCredParams as PublicKeyCredentialParameters[],
      timeout: optionsJSON.timeout,
      attestation: (optionsJSON.attestation as AttestationConveyancePreference) ?? 'none',
      authenticatorSelection: optionsJSON.authenticatorSelection as AuthenticatorSelectionCriteria | undefined,
      excludeCredentials: optionsJSON.excludeCredentials?.map((c) => ({
        type: 'public-key' as const,
        id: b64urlToBuffer(c.id),
      })),
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Passkey creation was cancelled');

  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    credential_id: bufferToB64url(credential.rawId),
    attestation_object: bufferToB64url(response.attestationObject),
    client_data_json: bufferToB64url(response.clientDataJSON),
  };
}

/** Run `navigator.credentials.get()` and return API-ready base64url fields. */
export async function getPasskeyAssertion(optionsJSON: RequestOptionsInput): Promise<{
  credential_id: string;
  authenticator_data: string;
  client_data_json: string;
  signature: string;
}> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: b64urlToBuffer(optionsJSON.challenge),
      rpId: optionsJSON.rpId,
      allowCredentials: optionsJSON.allowCredentials?.map((c) => ({
        type: 'public-key' as const,
        id: b64urlToBuffer(c.id),
      })),
      timeout: optionsJSON.timeout,
      userVerification: (optionsJSON.userVerification as UserVerificationRequirement) ?? 'required',
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Passkey sign-in was cancelled');

  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    credential_id: bufferToB64url(credential.rawId),
    authenticator_data: bufferToB64url(response.authenticatorData),
    client_data_json: bufferToB64url(response.clientDataJSON),
    signature: bufferToB64url(response.signature),
  };
}
