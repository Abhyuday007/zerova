import { api } from "./client";

function b64urlEncode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function b64urlDecode(str: string): ArrayBuffer {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

export async function registerBiometric(deviceName: string): Promise<{ registered: boolean }> {
  const options = await api.webauthn.registerBegin();

  const credential = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: b64urlDecode(options.challenge),
      user: {
        ...options.user,
        id: b64urlDecode(options.user.id),
      },
    },
  }) as PublicKeyCredential;

  const response = credential.response as AuthenticatorAttestationResponse;

  return api.webauthn.registerFinish({
    credential_id: b64urlEncode(credential.rawId),
    public_key: b64urlEncode(response.getPublicKey()!),
    attestation_object: b64urlEncode(response.attestationObject),
    client_data_json: b64urlEncode(response.clientDataJSON),
    device_name: deviceName,
  });
}

export async function authenticateBiometric(username: string): Promise<{ token: string; username: string }> {
  const options = await api.webauthn.authBegin(username);

  const assertion = await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: b64urlDecode(options.challenge),
      allowCredentials: options.allowCredentials.map((c: any) => ({
        ...c,
        id: b64urlDecode(c.id),
      })),
    },
  }) as PublicKeyCredential;

  const response = assertion.response as AuthenticatorAssertionResponse;

  return api.webauthn.authFinish({
    credential_id: b64urlEncode(assertion.rawId),
    authenticator_data: b64urlEncode(response.authenticatorData),
    client_data_json: b64urlEncode(response.clientDataJSON),
    signature: b64urlEncode(response.signature),
    username,
  });
}
