// Реализация Web Push (RFC 8291 + RFC 8292 VAPID) на встроенном модуле
// crypto — без npm-пакета web-push, чтобы сервер по-прежнему разворачивался
// на Render без единой внешней зависимости.
//
// Используется так:
//   const keys = getOrCreateVapidKeys(loadRaw, saveRaw);
//   await sendWebPush({ subscription, payload: {title, body}, vapid: keys, subject: "mailto:admin@example.com" });

const crypto = require("crypto");

function b64urlEncode(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecode(str) {
  str = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

// ---------- VAPID ключи (постоянная пара ключей сервера) ----------
function generateVapidKeys() {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  return {
    publicKey: b64urlEncode(ecdh.getPublicKey()), // 65 байт, несжатая точка
    privateKey: b64urlEncode(ecdh.getPrivateKey()), // 32 байта
  };
}

// data — объект { vapid: {publicKey, privateKey} } уже загруженный из базы;
// если ключей ещё нет — генерирует, вызывающий код должен сохранить data после этого.
function ensureVapidKeys(data) {
  if (!data.vapid || !data.vapid.publicKey || !data.vapid.privateKey) {
    data.vapid = generateVapidKeys();
    return { keys: data.vapid, created: true };
  }
  return { keys: data.vapid, created: false };
}

function vapidPrivateKeyObject(privateKeyB64url) {
  const d = b64urlDecode(privateKeyB64url);
  // Собираем PKCS8 DER-обёртку вручную для приватного ключа EC P-256,
  // чтобы получить KeyObject, который принимает crypto.sign().
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const pubPoint = ecdh.getPublicKey();
  // Собираем KeyObject через импорт JWK — Node поддерживает это нативно для EC-ключей,
  // это надёжнее самостоятельной сборки ASN.1/DER.
  const jwk = {
    kty: "EC",
    crv: "P-256",
    d: b64urlEncode(d),
    x: b64urlEncode(pubPoint.slice(1, 33)),
    y: b64urlEncode(pubPoint.slice(33, 65)),
  };
  return crypto.createPrivateKey({ key: jwk, format: "jwk" });
}

function buildVapidJwt(audience, subject, vapidKeys) {
  const header = { typ: "JWT", alg: "ES256" };
  const payload = {
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: subject || "mailto:admin@example.com",
  };
  const signingInput = b64urlEncode(JSON.stringify(header)) + "." + b64urlEncode(JSON.stringify(payload));
  const keyObj = vapidPrivateKeyObject(vapidKeys.privateKey);
  const signature = crypto.sign("sha256", Buffer.from(signingInput), { key: keyObj, dsaEncoding: "ieee-p1363" });
  return signingInput + "." + b64urlEncode(signature);
}

// ---------- шифрование полезной нагрузки (RFC 8291, content-encoding aes128gcm) ----------
function encryptPayload(plaintextBuf, subscriptionKeys) {
  const uaPublic = b64urlDecode(subscriptionKeys.p256dh); // 65 байт, точка подписчика
  const authSecret = b64urlDecode(subscriptionKeys.auth); // 16 байт

  const asEcdh = crypto.createECDH("prime256v1");
  asEcdh.generateKeys();
  const asPublic = asEcdh.getPublicKey(); // 65 байт — эфемерный публичный ключ сервера для этого сообщения
  const ecdhSecret = asEcdh.computeSecret(uaPublic);

  // HKDF #1: получаем "ikm" (input keying material) для второго HKDF
  const prkKey = crypto.createHmac("sha256", authSecret).update(ecdhSecret).digest();
  const keyInfo = Buffer.concat([
    Buffer.from("WebPush: info\0", "utf8"),
    uaPublic,
    asPublic,
  ]);
  const ikm = crypto.createHmac("sha256", prkKey).update(Buffer.concat([keyInfo, Buffer.from([1])])).digest().slice(0, 32);

  const salt = crypto.randomBytes(16);
  const prk = crypto.createHmac("sha256", salt).update(ikm).digest();

  const cekInfo = Buffer.from("Content-Encoding: aes128gcm\0", "utf8");
  const cek = crypto.createHmac("sha256", prk).update(Buffer.concat([cekInfo, Buffer.from([1])])).digest().slice(0, 16);

  const nonceInfo = Buffer.from("Content-Encoding: nonce\0", "utf8");
  const nonce = crypto.createHmac("sha256", prk).update(Buffer.concat([nonceInfo, Buffer.from([1])])).digest().slice(0, 12);

  // один-единственный "record": добавляем разделитель 0x02 в конец обычного текста (без паддинга)
  const padded = Buffer.concat([plaintextBuf, Buffer.from([0x02])]);
  const cipher = crypto.createCipheriv("aes-128-gcm", cek, nonce);
  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const cipherWithTag = Buffer.concat([ciphertext, authTag]);

  const rs = Buffer.alloc(4);
  rs.writeUInt32BE(4096, 0); // record size, с запасом (сообщение маленькое, влезает в один record)

  const header = Buffer.concat([
    salt,
    rs,
    Buffer.from([asPublic.length]), // idlen
    asPublic, // keyid — публичный ключ сервера для этого сообщения
  ]);

  return Buffer.concat([header, cipherWithTag]);
}

// ---------- отправка одного push-сообщения ----------
// subscription: { endpoint, keys: { p256dh, auth } }
// payload: любой JSON-сериализуемый объект (например {title, body})
// vapid: { publicKey, privateKey }
// Возвращает { ok:true } либо { ok:false, status, gone:true|false }
async function sendWebPush({ subscription, payload, vapid, subject }) {
  const endpoint = subscription.endpoint;
  const audience = new URL(endpoint).origin;
  const jwt = buildVapidJwt(audience, subject, vapid);
  const authHeader = `vapid t=${jwt}, k=${vapid.publicKey}`;

  const plaintext = Buffer.from(JSON.stringify(payload || {}), "utf8");
  const body = encryptPayload(plaintext, subscription.keys);

  const resp = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Encoding": "aes128gcm",
      TTL: "86400",
      Authorization: authHeader,
    },
    body,
  });
  if (resp.ok) return { ok: true, status: resp.status };
  // 404/410 — подписка больше не существует (например, пользователь удалил разрешение) — её нужно удалить у нас
  return { ok: false, status: resp.status, gone: resp.status === 404 || resp.status === 410 };
}

module.exports = { generateVapidKeys, ensureVapidKeys, buildVapidJwt, encryptPayload, sendWebPush, b64urlEncode, b64urlDecode };
