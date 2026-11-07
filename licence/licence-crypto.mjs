const encoder = new TextEncoder();
export const APP_ID = 'com.salmanbashir.cleanup8002';
export const ITERATIONS = 600000;
export const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuRlk9kq6G8W2HO4rs11Y
+0mX7xG5OSlb8zsF4MCrt4f89kYws3CSph11LAmIbN7oZv83ugVIeNi/oTJdYzTo
p+Nq7KWZr2w2d7lR4zlyNaZyXv11QwCgPYn+2AENwKTJr7c85DY5gcuIbUVAhulY
whhwOcwaWxfZH2CnBUWVGOuDq66vsPoLmsAEucqsIUC7l+57sJDWIk2crWmgi61u
S+HLTw8h91PqtGMzpIAWhw8Xm4HajggPW6dDhof7FgUot9XJ2YDMQanrnfaZDl2F
DkEMWiAFdxyeHfWA+tHhDnsbARY2/A3cFw3V72LADkyTFkQ0vaw7viQkSf0NbXRk
fQIDAQAB
-----END PUBLIC KEY-----`;
const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
export const encode64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
export function decode64(value) {
  if (typeof value !== 'string' || value.length > 30000 || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('Invalid encrypted key format.');
  return Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
}
function pemBytes(pem) { return Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')), c => c.charCodeAt(0)); }
export function normaliseUnlockCode(value) { return String(value).replace(/[\s-]/g, '').toUpperCase(); }
export async function unlockOwnerKey(bundle, input, publicPem = PUBLIC_KEY_PEM) {
  if (!globalThis.crypto?.subtle) throw Error('Open this page in Chrome using its https:// address.');
  const code = normaliseUnlockCode(input);
  if (!/^[A-Z2-7]{32}$/.test(code)) throw Error('Paste the complete owner unlock code from your chat.');
  if (bundle.version !== 1 || bundle.kdf !== 'PBKDF2-SHA256' || bundle.iterations !== ITERATIONS || bundle.cipher !== 'AES-256-GCM') throw Error('Unsupported encrypted key backup.');
  const salt = decode64(bundle.salt), iv = decode64(bundle.iv);
  if (salt.length !== 16 || iv.length !== 12) throw Error('Invalid encrypted key backup.');
  const material = await crypto.subtle.importKey('raw', encoder.encode(code), 'PBKDF2', false, ['deriveKey']);
  const wrappingKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode('8002CleanUp-owner-key:v1:' + APP_ID) }, wrappingKey, decode64(bundle.ciphertext)));
  } catch { throw Error('Unlock code is incorrect, or the encrypted backup has changed.'); }
  try {
    const key = await crypto.subtle.importKey('pkcs8', plain, algorithm, false, ['sign']);
    const publicKey = await crypto.subtle.importKey('spki', pemBytes(publicPem), algorithm, false, ['verify']);
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const signature = await crypto.subtle.sign(algorithm, key, challenge);
    if (!await crypto.subtle.verify(algorithm, publicKey, signature, challenge)) throw Error('This signing key does not match the Android app.');
    return key;
  } finally { plain.fill(0); }
}
export async function issueLicence(key, { name, device, days, allowUnbound = false }, now = Date.now()) {
  name = String(name ?? '').trim(); device = String(device ?? '').trim().toUpperCase(); days = Number(days);
  if (!name || name.length > 100) throw Error('Enter a customer name between 1 and 100 characters.');
  if (device === '*' ? !allowUnbound : !/^[A-F0-9]{20}$/.test(device)) throw Error('Copy the exact 20-character device code from the Android app.');
  if (![0, 30, 365].includes(days)) throw Error('Choose lifetime, 30 days or 365 days.');
  if (!Number.isSafeInteger(now) || now <= 0) throw Error('Set the correct date and time on this device.');
  const payload = { v: 1, app: APP_ID, id: crypto.randomUUID(), tier: 'pro', name, device, issuedAt: now, expiresAt: days ? now + days * 86400000 : 0 };
  const encoded = encode64(encoder.encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign(algorithm, key, encoder.encode(encoded));
  return { token: '8002.' + encoded + '.' + encode64(signature), payload };
}
export async function verifyLicence(token, publicPem = PUBLIC_KEY_PEM) {
  const pieces = token.split('.');
  if (pieces.length !== 3 || pieces[0] !== '8002') return false;
  const publicKey = await crypto.subtle.importKey('spki', pemBytes(publicPem), algorithm, false, ['verify']);
  return crypto.subtle.verify(algorithm, publicKey, decode64(pieces[2]), encoder.encode(pieces[1]));
}
