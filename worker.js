// ======================================================
// TITIPUUY API v0.7.1 — Order Management Integration
// Firebase Authentication
// Firebase Admin REST API
// Mitra Application & Admin Approval
// Cloudflare Workers
// ======================================================
const VERSION = "0.8.5";



const ALLOWED_ORIGINS = [

  "https\://refidhenaldi126-bot.github.io"

];



const FIREBASE_KEYS_URL =

  "https\://www\.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";



const GOOGLE_TOKEN_URL =

  "https\://oauth2.googleapis.com/token";



const FIREBASE_SCOPE = [

  "https\://www\.googleapis.com/auth/userinfo.email",

  "https\://www\.googleapis.com/auth/firebase.database"

].join(" ");



let firebaseKeysCache = null;

let firebaseKeysExpiry = 0;



let adminTokenCache = null;

let adminTokenExpiry = 0;





// ======================================================
// RESPONSE
// ======================================================
// Whitelist responses so future encrypted NIK/document fields never leak.
function safeMitraStatus(application) {
  if (!application || typeof application !== "object") return null;
  return {
    status: application.status || null,
    submittedAt: Number.isFinite(application.submittedAt) ? application.submittedAt : null,
    reviewedAt: Number.isFinite(application.reviewedAt) ? application.reviewedAt : null,
    rejectionReason: typeof application.rejectionReason === "string" ? application.rejectionReason : null,
    rejectedAt: Number.isFinite(application.rejectedAt) ? application.rejectedAt : null,
    reapplyAvailableAt: Number.isFinite(application.reapplyAvailableAt) ? application.reapplyAvailableAt : (application.status === "rejected" ? Number(application.rejectedAt || application.reviewedAt || 0) + 7 * 24 * 60 * 60 * 1000 : null),
    canReapply: application.status === "rejected" && Date.now() >= (Number(application.reapplyAvailableAt) || (Number(application.rejectedAt || application.reviewedAt || 0) + 7 * 24 * 60 * 60 * 1000))
  };
}

function safeAdminApplication(uid, application) {
  if (!application || typeof application !== "object") return { uid };
  return {
    uid,
    fullName: typeof application.fullName === "string" ? application.fullName : "",
    phone: typeof application.phone === "string" ? application.phone : "",
    vehicleType: typeof application.vehicleType === "string" ? application.vehicleType : "",
    vehicleNumber: typeof application.vehicleNumber === "string" ? application.vehicleNumber : "",
    address: typeof application.address === "string" ? application.address : "",
    status: application.status || "unknown",
    submittedAt: Number.isFinite(application.submittedAt) ? application.submittedAt : null,
    reviewedAt: Number.isFinite(application.reviewedAt) ? application.reviewedAt : null,
    rejectionReason: typeof application.rejectionReason === "string" ? application.rejectionReason : null,
    rejectedAt: Number.isFinite(application.rejectedAt) ? application.rejectedAt : null,
    reapplyAvailableAt: Number.isFinite(application.reapplyAvailableAt) ? application.reapplyAvailableAt : null,
    reviewedBy: typeof application.reviewedBy === "string" ? application.reviewedBy : null,
    reverifiedAt: Number.isFinite(application.reverifiedAt) ? application.reverifiedAt : null,
    reverifiedBy: typeof application.reverifiedBy === "string" ? application.reverifiedBy : null,
    reviewHistory: application.reviewHistory && typeof application.reviewHistory === "object"
      ? Object.values(application.reviewHistory).slice(-10).map(entry => ({
          previousStatus: typeof entry?.previousStatus === "string" ? entry.previousStatus : null,
          newStatus: typeof entry?.newStatus === "string" ? entry.newStatus : null,
          reviewType: typeof entry?.reviewType === "string" ? entry.reviewType : "standard",
          reviewedAt: Number.isFinite(entry?.reviewedAt) ? entry.reviewedAt : null,
          reviewedBy: typeof entry?.reviewedBy === "string" ? entry.reviewedBy : null,
          verificationNote: typeof entry?.verificationNote === "string" ? entry.verificationNote : null,
          previousRejectionReason: typeof entry?.previousRejectionReason === "string" ? entry.previousRejectionReason : null,
          rejectionReason: typeof entry?.rejectionReason === "string" ? entry.rejectionReason : null
        })) : [],
    hasNik: Boolean(application.nikEncrypted && typeof application.nikEncrypted === "object" && typeof application.nikEncrypted.ciphertext === "string" && typeof application.nikEncrypted.iv === "string"),
    hasKtpDocument: typeof application.ktpObjectKey === "string" && application.ktpObjectKey.length > 0,
    hasSelfieKtp: typeof application.selfieKtpObjectKey === "string" && application.selfieKtpObjectKey.length > 0,
    hasStnk: typeof application.stnkObjectKey === "string" && application.stnkObjectKey.length > 0
  };
}

// ======================================================
// PRIVATE MITRA DOCUMENT HELPERS (v0.5.1)
// ======================================================
function decodeBase64Strict(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("MITRA_NIK_ENCRYPTION_KEY must be standard Base64");
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  if (bytes.length !== 32) throw new Error("MITRA_NIK_ENCRYPTION_KEY must decode to exactly 32 bytes");
  return bytes;
}

async function encryptNik(nik, env) {
  if (!env.MITRA_NIK_ENCRYPTION_KEY) throw new Error("NIK encryption is not configured");
  const rawKey = decodeBase64Strict(env.MITRA_NIK_ENCRYPTION_KEY);
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(nik);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
  return { algorithm: "A256GCM", iv: b64(iv), ciphertext: b64(ciphertext), version: 1 };
}

async function decryptNik(encrypted, env) {
  if (!env.MITRA_NIK_ENCRYPTION_KEY) throw new Error("NIK encryption is not configured");
  if (!encrypted || encrypted.algorithm !== "A256GCM" || encrypted.version !== 1) throw new Error("Unsupported encrypted NIK format");
  const rawKey = decodeBase64Strict(env.MITRA_NIK_ENCRYPTION_KEY);
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const fromB64 = (value) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(encrypted.iv) }, key, fromB64(encrypted.ciphertext));
  return new TextDecoder().decode(plaintext);
}

function detectImageType(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a) return "image/png";
  return null;
}

function randomObjectKey(uid) {
  return `mitra-documents/${uid}/${crypto.randomUUID()}.bin`;
}

async function writeAdminAudit(env, adminUid, action, targetUid, details = {}) {
  const auditId = `${Date.now()}_${crypto.randomUUID()}`;
  await adminDatabaseRequest(`adminAudit/${auditId}`, "PUT", env, {
    actorUid: adminUid,
    action,
    targetUid,
    createdAt: Date.now(),
    details
  });
}

function privateFileResponse(object, contentType) {
  const headers = new Headers({
    "Content-Type": contentType,
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; sandbox"
  });
  return new Response(object.body, { status: 200, headers });
}

function jsonResponse(data, status = 200, headers = {}) {

  return new Response(JSON.stringify(data), {

    status,

    headers: {

      "Content-Type": "application/json; charset=utf-8",

      "Cache-Control": "no-store",

      ...headers

    }

  });

}





// ======================================================
// CORS
// ======================================================
function corsHeaders(request) {

  const origin = request.headers.get("Origin");



  const headers = {

    "Vary": "Origin",

    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",

    "Access-Control-Allow-Headers": "Authorization, Content-Type",

    "Access-Control-Max-Age": "86400"

  };



  if (origin && ALLOWED_ORIGINS.includes(origin)) {

    headers["Access-Control-Allow-Origin"] = origin;

  }



  return headers;

}



function isAllowedOrigin(request) {

  const origin = request.headers.get("Origin");



  return !origin || ALLOWED_ORIGINS.includes(origin);

}





// ======================================================
// BASE64URL
// ======================================================
function base64UrlEncode(bytes) {

  const data = new Uint8Array(bytes);



  let binary = "";



  for (const byte of data) {

    binary += String.fromCharCode(byte);

  }



  return btoa(binary)

    .replace(/\+/g, "-")

    .replace(/\//g, "_")

    .replace(/=+$/g, "");

}



function base64UrlEncodeText(text) {

  return base64UrlEncode(

    new TextEncoder().encode(text)

  );

}



function decodeBase64Url(value) {

  const base64 = value

    .replace(/-/g, "+")

    .replace(/_/g, "/");



  const padded = base64.padEnd(

    Math.ceil(base64.length / 4) * 4,

    "="

  );



  const binary = atob(padded);



  const bytes = new Uint8Array(binary.length);



  for (let i = 0; i < binary.length; i++) {

    bytes[i] = binary.charCodeAt(i);

  }



  return bytes;

}



function decodeJwtPart(value) {

  return JSON.parse(

    new TextDecoder().decode(

      decodeBase64Url(value)

    )

  );

}





// ======================================================
// FIREBASE PUBLIC KEYS
// ======================================================
async function getFirebaseKeys() {

  if (

    firebaseKeysCache &&

    Date.now() < firebaseKeysExpiry

  ) {

    return firebaseKeysCache;

  }



  const response = await fetch(FIREBASE_KEYS_URL);



  if (!response.ok) {

    throw new Error(

      "Unable to retrieve Firebase public keys"

    );

  }



  const keys = await response.json();



  const cacheControl =

    response.headers.get("Cache-Control") || "";



  const match = cacheControl.match(/max-age=(\d+)/);



  const maxAge = match

    ? Number(match[1])

    : 3600;



  firebaseKeysCache = keys;



  firebaseKeysExpiry =

    Date.now() + maxAge * 1000;



  return keys;

}





// ======================================================
// VERIFY FIREBASE ID TOKEN
// ======================================================
async function verifyFirebaseToken(token, env) {

  if (!token) {

    throw new Error("Missing Firebase ID Token");

  }



  const parts = token.split(".");



  if (parts.length !== 3) {

    throw new Error("Invalid JWT structure");

  }



  const header = decodeJwtPart(parts[0]);

  const payload = decodeJwtPart(parts[1]);



  const projectId = env.FIREBASE_PROJECT_ID;



  if (!projectId) {

    throw new Error("Firebase project ID missing");

  }



  if (

    header.alg !== "RS256" ||

    !header.kid

  ) {

    throw new Error("Invalid JWT algorithm");

  }



  if (

    payload.iss !==

      `https\://securetoken.google.com/${projectId}` ||

    payload.aud !== projectId

  ) {

    throw new Error("Invalid token issuer or audience");

  }



  const now = Math.floor(Date.now() / 1000);



  if (

    !payload.sub ||

    payload.sub.length > 128 ||

    !Number.isFinite(payload.exp) ||

    !Number.isFinite(payload.iat) ||

    !Number.isFinite(payload.auth_time) ||

    payload.exp <= now ||

    payload.iat > now + 60 ||

    payload.auth_time > now + 60

  ) {

    throw new Error("Invalid or expired Firebase token");

  }



  if (

    payload.user_id &&

    payload.user_id !== payload.sub

  ) {

    throw new Error("Firebase UID mismatch");

  }



  const keys = await getFirebaseKeys();



  let jwk = keys.keys.find(

    key => key.kid === header.kid

  );



  if (!jwk) {

    firebaseKeysCache = null;

    firebaseKeysExpiry = 0;



    const refreshed = await getFirebaseKeys();



    jwk = refreshed.keys.find(

      key => key.kid === header.kid

    );

  }



  if (!jwk) {

    throw new Error("Firebase signing key not found");

  }



  const publicKey = await crypto.subtle.importKey(

    "jwk",

    jwk,

    {

      name: "RSASSA-PKCS1-v1_5",

      hash: "SHA-256"

    },

    false,

    ["verify"]

  );



  const valid = await crypto.subtle.verify(

    "RSASSA-PKCS1-v1_5",

    publicKey,

    decodeBase64Url(parts[2]),

    new TextEncoder().encode(

      `${parts[0]}.${parts[1]}`

    )

  );



  if (!valid) {

    throw new Error("Invalid Firebase signature");

  }



  return {

    uid: payload.sub,

    email: payload.email || null,

    name: payload.name || null,

    emailVerified: payload.email_verified === true

  };

}





// ======================================================
// FIREBASE AUTHENTICATION
// ======================================================
function getBearerToken(request) {

  const authorization =

    request.headers.get("Authorization");



  const match = authorization?.match(

    /^Bearer\s+(.+)$/i

  );



  return match ? match[1].trim() : null;

}



async function authenticate(request, env) {

  const token = getBearerToken(request);



  if (!token) {

    return {

      success: false,

      response: jsonResponse(

        {

          success: false,

          error: "Authorization required"

        },

        401

      )

    };

  }



  try {

    const user = await verifyFirebaseToken(token, env);



    return {

      success: true,

      user,

      token

    };



  } catch (error) {

    return {

      success: false,

      response: jsonResponse(

        {

          success: false,

          error: "Authentication failed",

          details: error.message

        },

        401

      )

    };

  }

}





// ======================================================
// FIREBASE ADMIN SERVICE ACCOUNT
// ======================================================
function pemToArrayBuffer(pem) {

  if (!pem || typeof pem !== "string") {

    throw new Error("Invalid private key");

  }



  const base64 = pem

    .replace(/-----BEGIN PRIVATE KEY-----/g, "")

    .replace(/-----END PRIVATE KEY-----/g, "")

    .replace(/\s/g, "");



  const bytes = decodeBase64Url(base64);



  return bytes.buffer.slice(

    bytes.byteOffset,

    bytes.byteOffset + bytes.byteLength

  );

}





// ======================================================
// GOOGLE OAUTH ACCESS TOKEN
// ======================================================
async function createAdminAccessToken(env) {

  if (

    adminTokenCache &&

    Date.now() < adminTokenExpiry

  ) {

    return adminTokenCache;

  }



  const raw = env.FIREBASE_SERVICE_ACCOUNT_JSON;



  if (!raw) {

    throw new Error("Firebase Admin Secret missing");

  }



  let serviceAccount;



  try {

    serviceAccount = JSON.parse(raw);

  } catch {

    throw new Error("Invalid Service Account JSON");

  }



  if (

    serviceAccount.type !== "service_account" ||

    serviceAccount.project_id !== env.FIREBASE_PROJECT_ID ||

    !serviceAccount.client_email ||

    !serviceAccount.private_key ||

    !serviceAccount.private_key_id

  ) {

    throw new Error("Invalid Firebase Service Account configuration");

  }



  const now = Math.floor(Date.now() / 1000);



  const header = {

    alg: "RS256",

    typ: "JWT",

    kid: serviceAccount.private_key_id

  };



  const claims = {

    iss: serviceAccount.client_email,

    scope: FIREBASE_SCOPE,

    aud: GOOGLE_TOKEN_URL,

    iat: now,

    exp: now + 3600

  };



  const unsignedToken =

    base64UrlEncodeText(JSON.stringify(header)) +

    "." +

    base64UrlEncodeText(JSON.stringify(claims));



  const privateKey = await crypto.subtle.importKey(

    "pkcs8",

    pemToArrayBuffer(serviceAccount.private_key),

    {

      name: "RSASSA-PKCS1-v1_5",

      hash: "SHA-256"

    },

    false,

    ["sign"]

  );



  const signature = await crypto.subtle.sign(

    "RSASSA-PKCS1-v1_5",

    privateKey,

    new TextEncoder().encode(unsignedToken)

  );



  const assertion =

    unsignedToken + "." + base64UrlEncode(signature);



  const response = await fetch(GOOGLE_TOKEN_URL, {

    method: "POST",

    headers: {

      "Content-Type": "application/x-www-form-urlencoded"

    },

    body: new URLSearchParams({

      grant_type:

        "urn:ietf:params:oauth:grant-type:jwt-bearer",

      assertion

    })

  });



  const result = await response.json();



  if (!response.ok) {

    throw new Error(

      `Google OAuth error ${response.status}: ${

        result.error_description || result.error || "Unknown error"

      }`

    );

  }



  if (!result.access_token) {

    throw new Error("Google OAuth did not return an access token");

  }



  adminTokenCache = result.access_token;



  adminTokenExpiry =

    Date.now() + (result.expires_in - 120) * 1000;



  return adminTokenCache;

}





// ======================================================
// FIREBASE ADMIN DATABASE REQUEST
// ======================================================
async function adminDatabaseRequest(

  path,

  method,

  env,

  body = undefined

) {

  const accessToken = await createAdminAccessToken(env);



  const databaseUrl =

    env.FIREBASE_DATABASE_URL.replace(/\/+$/, "");



  if (!databaseUrl.startsWith("https\://")) {

    throw new Error("Invalid Firebase Database URL");

  }



  const cleanPath = path

    ? path.replace(/^\/+/, "")

    : "";



  const endpoint = new URL(

    `${databaseUrl}/${cleanPath}.json`

  );



  const options = {

    method,

    headers: {

      "Accept": "application/json",

      "Authorization": `Bearer ${accessToken}`

    }

  };



  if (body !== undefined) {

    options.headers["Content-Type"] = "application/json";

    options.body = JSON.stringify(body);

  }



  const response = await fetch(

    endpoint.toString(),

    options

  );



  if (!response.ok) {

    const errorBody = await response.text();



    // Retry once if the cached token is rejected.
    if (

      response.status === 401 &&

      adminTokenCache === accessToken

    ) {

      adminTokenCache = null;

      adminTokenExpiry = 0;



      const newToken = await createAdminAccessToken(env);



      options.headers.Authorization =

        `Bearer ${newToken}`;



      const retry = await fetch(

        endpoint.toString(),

        options

      );



      if (!retry.ok) {

        const retryBody = await retry.text();



        throw new Error(

          `Firebase Admin Database error: ${retry.status} - ${retryBody.slice(0, 1000)}`

        );

      }



      return await retry.json();

    }



    throw new Error(

      `Firebase Admin Database error: ${response.status} - ${errorBody.slice(0, 1000)}`

    );

  }



  return await response.json();

}





// ======================================================
// ADMIN CHECK
// ======================================================
function isAdmin(user, env) {

  return Boolean(

    env.ADMIN_UID &&

    user.uid === env.ADMIN_UID

  );

}



async function requireAdmin(request, env) {

  const auth = await authenticate(request, env);



  if (!auth.success) {

    return auth;

  }



  if (!isAdmin(auth.user, env)) {

    return {

      success: false,

      response: jsonResponse(

        {

          success: false,

          error: "Admin access denied"

        },

        403

      )

    };

  }



  return auth;

}





// ======================================================
// ROLE MANAGEMENT
// ======================================================
// A stored role is NOT proof of Mitra approval. Derive the privileged role
// only from the Admin-reviewed application + matching active mitra profile.
async function hasValidMitraApproval(uid, env) {
  const safeUid = encodeURIComponent(uid);
  const [application, mitraProfile] = await Promise.all([
    adminDatabaseRequest(`mitraApplications/${safeUid}`, "GET", env),
    adminDatabaseRequest(`mitraProfiles/${safeUid}`, "GET", env)
  ]);
  return Boolean(
    application && application.status === "approved" &&
    typeof application.reviewedBy === "string" && application.reviewedBy.length > 0 &&
    Number.isFinite(application.reviewedAt) &&
    mitraProfile && mitraProfile.status === "active" &&
    mitraProfile.approvedBy === application.reviewedBy &&
    Number.isFinite(mitraProfile.approvedAt) &&
    mitraProfile.approvedAt === application.reviewedAt &&
    mitraProfile.fullName === application.fullName &&
    mitraProfile.phone === application.phone &&
    mitraProfile.vehicleType === application.vehicleType &&
    mitraProfile.vehicleNumber === application.vehicleNumber
  );
}

async function getUserRole(uid, env) {
  const rolePath = `users/${encodeURIComponent(uid)}/role`;
  const storedRole = await adminDatabaseRequest(rolePath, "GET", env);

  // Fail closed: only a valid Admin approval can produce the Mitra role.
  if (await hasValidMitraApproval(uid, env)) {
    if (storedRole !== "Mitra") {
      await adminDatabaseRequest(rolePath, "PUT", env, "Mitra");
    }
    return "Mitra";
  }

  // Repair stale/legacy/self-assigned Mitra roles to the safe default.
  if (storedRole !== "Pembeli") {
    await adminDatabaseRequest(rolePath, "PUT", env, "Pembeli");
  }
  return "Pembeli";
}





// ======================================================
// REQUEST BODY
// ======================================================
async function readJson(request, maxChars = 20000) {

  const contentType =

    request.headers.get("Content-Type") || "";



  if (!contentType.includes("application/json")) {

    throw new Error("Content-Type must be application/json");

  }



  const text = await request.text();



  if (text.length > maxChars) {

    throw new Error("Request body too large");

  }



  return JSON.parse(text);

}





// ======================================================
// ORDER MANAGEMENT v0.7.0 — server-owned sequence + creation
// ======================================================
function jakartaYearParts(timestamp = Date.now()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Jakarta", year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(new Date(timestamp));
  const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return { year: Number(values.year), yearShort: values.year.slice(-2) };
}

async function nextPublicOrderId(env) {
  const { year, yearShort } = jakartaYearParts();
  const accessToken = await createAdminAccessToken(env);
  const databaseUrl = env.FIREBASE_DATABASE_URL.replace(/\/+$/, "");
  const endpoint = `${databaseUrl}/orderSequences/${year}.json`;

  // Firebase conditional writes (ETag / If-Match) provide compare-and-swap.
  // This prevents concurrent requests from receiving the same sequence.
  for (let attempt = 0; attempt < 12; attempt++) {
    const read = await fetch(endpoint, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "X-Firebase-ETag": "true",
        "Accept": "application/json"
      }
    });
    if (!read.ok) throw new Error(`Order sequence read failed (${read.status})`);
    const current = await read.json();
    const etag = read.headers.get("ETag");
    if (!etag) throw new Error("Firebase did not return an ETag for order sequence");
    const next = (Number.isSafeInteger(current) && current >= 0 ? current : 0) + 1;
    if (!Number.isSafeInteger(next)) throw new Error("Order sequence limit reached");

    const write = await fetch(endpoint, {
      method: "PUT",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "If-Match": etag
      },
      body: JSON.stringify(next)
    });
    if (write.status === 412) continue; // another request won; reread and retry
    if (!write.ok) throw new Error(`Order sequence write failed (${write.status})`);
    return `TU-${String(next).padStart(2, "0")}-${yearShort}`;
  }
  throw new Error("Nomor pesanan sedang padat. Silakan coba kembali.");
}

function cleanPoint(p) {
  if (!p || typeof p !== "object") return null;
  const lat = Number(p.lat), lng = Number(p.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) return null;
  return { lat: Math.round(lat * 1e6) / 1e6, lng: Math.round(lng * 1e6) / 1e6 };
}
// Titik tujuan untuk papan order dibulatkan (~110 m) agar alamat pembeli tidak bocor sebelum order diterima.
function roughPoint(p) {
  return p ? { lat: Math.round(p.lat * 1e3) / 1e3, lng: Math.round(p.lng * 1e3) / 1e3 } : null;
}

function cleanOrderItems(items) {
  if (!Array.isArray(items) || items.length < 1 || items.length > 30) {
    throw new Error("Daftar barang pesanan tidak valid.");
  }
  return items.map(item => {
    const name = String(item?.name || "").trim().slice(0, 120);
    const place = String(item?.place || "").trim().slice(0, 120);
    const price = Number(item?.price);
    const qty = Number(item?.qty);
    if (!name || !place || !Number.isSafeInteger(price) || price < 0 ||
        !Number.isSafeInteger(qty) || qty < 1 || qty > 99) {
      throw new Error("Ada barang dengan nama, harga, atau jumlah tidak valid.");
    }
    return { name, place, price, qty, emoji: String(item?.emoji || "🛍️").slice(0, 8) };
  });
}

async function createBuyerOrder(request, env) {
  const auth = await authenticate(request, env);
  if (!auth.success) return auth.response;
  const uid = auth.user.uid;
  if (await getUserRole(uid, env) !== "Pembeli") {
    return jsonResponse({ success: false, error: "Gunakan Mode Pembeli untuk membuat pesanan." }, 403);
  }

  let body;
  try { body = await readJson(request, 30000); }
  catch { return jsonResponse({ success: false, error: "Data pesanan tidak valid atau terlalu besar." }, 400); }

  try {
    const items = cleanOrderItems(body.items);
    const subtotal = items.reduce((sum, item) => sum + item.price * item.qty, 0);
    if (!Number.isSafeInteger(subtotal) || subtotal > 100000000) throw new Error("Total pesanan tidak valid.");
    const address = body.address;
    if (!address || typeof address !== "object") throw new Error("Alamat pengantaran wajib diisi.");
    const recipient = String(address.name || "").trim().slice(0, 100);
    const phone = String(address.phone || "").trim().slice(0, 20);
    const detail = String(address.detail || "").trim().slice(0, 500);
    if (recipient.length < 2 || !/^\+?[0-9][0-9\s-]{7,18}$/.test(phone) || detail.length < 5) {
      throw new Error("Nama penerima, nomor telepon, atau alamat tidak valid.");
    }

    // Consume sequence first. If a later write fails, the number is intentionally
    // skipped and never reused, including for cancelled/failed order attempts.
    const pickupPoint = cleanPoint(body.pickupPoint);
    const destPoint = cleanPoint(address.point);
    const id = await nextPublicOrderId(env);
    const now = Date.now();
    const key = crypto.randomUUID().replace(/-/g, "");
    const payment = String(body.payment || "Tunai (COD)").slice(0, 40);
    const customerNote = String(body.customerNote || "").trim().slice(0, 500);
    const name = items.map(item => `${item.name} × ${item.qty}`).join(", ").slice(0, 500);
    const places = [...new Set(items.map(item => item.place))];
    const order = {
      id, buyerUid: uid, mitraUid: null, date: new Date(now).toLocaleString("id-ID", { timeZone: "Asia/Jakarta" }),
      createdAt: now, updatedAt: now, name,
      place: places.length === 1 ? places[0] : "Beberapa tempat", emoji: "🛍️", total: subtotal,
      status: "Menunggu mitra", payment, customerNote, note: "Pesanan baru dibuat. Menunggu mitra menerima.",
      steps: ["Pesanan dibuat", "Menunggu mitra menerima pesanan"],
      address: { label: String(address.label || "Alamat").slice(0, 50), name: recipient, phone, detail,
        note: String(address.note || "").trim().slice(0, 250), ...(destPoint ? { point: destPoint } : {}) }, items,
      ...(pickupPoint ? { pickupPoint } : {})
    };
    const board = {
      id, buyerUid: uid, mitraUid: null, name, place: order.place, total: subtotal,
      status: order.status, createdAt: now,
      ...(pickupPoint ? { pickupPoint } : {}), ...(destPoint ? { deliveryPreviewPoint: roughPoint(destPoint) } : {})
    };
    const updates = {};
    updates[`orders/${key}`] = order;
    updates[`ordersByBuyer/${uid}/${key}`] = order;
    updates[`orderBoard/${key}`] = board;
    await adminDatabaseRequest("", "PATCH", env, updates);
    return jsonResponse({ success: true, order: { ...order, _key: key } }, 201);
  } catch (error) {
    return jsonResponse({ success: false, error: error.message || "Pesanan gagal dibuat." }, 400);
  }
}


// ======================================================
// ORDER MANAGEMENT v0.8.0 — buyer API, Mitra board, atomic claim/status
// ======================================================
async function conditionalOrderBoardUpdate(orderKey, uid, mode, nextStatus, env) {
  const accessToken = await createAdminAccessToken(env);
  const base = env.FIREBASE_DATABASE_URL.replace(/\/+$/, "");
  const endpoint = `${base}/orderBoard/${encodeURIComponent(orderKey)}.json`;
  for (let attempt = 0; attempt < 10; attempt++) {
    const read = await fetch(endpoint, { headers: { Authorization: `Bearer ${accessToken}`, "X-Firebase-ETag": "true", Accept: "application/json" } });
    if (!read.ok) throw new Error(`Gagal membaca papan pesanan (${read.status}).`);
    const board = await read.json();
    const etag = read.headers.get("ETag");
    if (!board || !etag) return { conflict: true };
    if (mode === "claim") {
      if (board.mitraUid || board.status !== "Menunggu mitra") return { conflict: true };
      board.mitraUid = uid;
      board.status = "Diterima";
    } else {
      if (board.mitraUid !== uid) return { forbidden: true };
      const allowed = { Diterima: "Disiapkan", Disiapkan: "Dalam perjalanan", "Dalam perjalanan": "Selesai" };
      if (allowed[board.status] !== nextStatus) return { conflict: true };
      board.status = nextStatus;
    }
    board.updatedAt = Date.now();
    const write = await fetch(endpoint, { method: "PUT", headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json", "If-Match": etag }, body: JSON.stringify(board) });
    if (write.status === 412) continue;
    if (!write.ok) throw new Error(`Gagal mengunci pesanan (${write.status}).`);
    return { board };
  }
  throw new Error("Pesanan sedang diproses Mitra lain. Coba lagi.");
}

async function acquireMitraOrderSlot(uid, orderKey, env, allowStaleReplace = false) {
  const token = await createAdminAccessToken(env);
  const url = `${env.FIREBASE_DATABASE_URL.replace(/\/+$/, "")}/mitraActiveOrder/${encodeURIComponent(uid)}.json`;
  for (let i = 0; i < 8; i++) {
    const read = await fetch(url, { headers:{ Authorization:`Bearer ${token}`, "X-Firebase-ETag":"true", Accept:"application/json" } });
    if (!read.ok) throw new Error(`Gagal memeriksa slot Mitra (${read.status}).`);
    const current = await read.json();
    const etag = read.headers.get("ETag");
    if (!etag) throw new Error("Firebase tidak mengembalikan ETag slot Mitra.");
    if (current) {
      const stale = Date.now() - Number(current.reservedAt || 0) > 60 * 1000;
      if (!allowStaleReplace || !stale) return false;
    }
    const write = await fetch(url, { method:"PUT", headers:{ Authorization:`Bearer ${token}`, "Content-Type":"application/json", "If-Match":etag }, body:JSON.stringify({ orderKey, reservedAt:Date.now() }) });
    if (write.status === 412) continue;
    if (!write.ok) throw new Error(`Gagal mengunci slot Mitra (${write.status}).`);
    return true;
  }
  return false;
}

async function releaseMitraOrderSlot(uid, orderKey, env) {
  const token = await createAdminAccessToken(env);
  const url = `${env.FIREBASE_DATABASE_URL.replace(/\/+$/, "")}/mitraActiveOrder/${encodeURIComponent(uid)}.json`;
  const read = await fetch(url, { headers:{ Authorization:`Bearer ${token}`, "X-Firebase-ETag":"true", Accept:"application/json" } });
  if (!read.ok) throw new Error(`Gagal membaca slot Mitra (${read.status}).`);
  const current = await read.json();
  const etag = read.headers.get("ETag");
  if (current?.orderKey !== orderKey || !etag) return;
  const write = await fetch(url, { method:"PUT", headers:{ Authorization:`Bearer ${token}`, "Content-Type":"application/json", "If-Match":etag }, body:"null" });
  if (!write.ok && write.status !== 412) throw new Error(`Gagal melepas slot Mitra (${write.status}).`);
}

async function expireWaitingOrders(rows, env) {
  const now = Date.now();
  for (const [key, order] of Object.entries(rows || {})) {
    if (!order || order.status !== "Menunggu mitra" || order.mitraUid || !Number(order.createdAt) || now - Number(order.createdAt) < 15 * 60 * 1000) continue;
    const token = await createAdminAccessToken(env);
    const base = env.FIREBASE_DATABASE_URL.replace(/\/+$/, "");
    const endpoint = `${base}/orderBoard/${encodeURIComponent(key)}.json`;
    for (let attempt = 0; attempt < 4; attempt++) {
      const read = await fetch(endpoint, { headers: { Authorization: `Bearer ${token}`, "X-Firebase-ETag": "true", Accept: "application/json" } });
      if (!read.ok) break;
      const board = await read.json(); const etag = read.headers.get("ETag");
      if (!board || !etag || board.status !== "Menunggu mitra" || board.mitraUid) break;
      board.status = "Tidak mendapat mitra"; board.updatedAt = now;
      const write = await fetch(endpoint, { method: "PUT", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "If-Match": etag }, body: JSON.stringify(board) });
      if (write.status === 412) continue;
      if (!write.ok) break;
      const full = await adminDatabaseRequest(`orders/${encodeURIComponent(key)}`, "GET", env);
      if (!full) break;
      const updated = { ...full, status: "Tidak mendapat mitra", note: "Belum ada Mitra yang menerima dalam 15 menit.", updatedAt: now, steps: [...(Array.isArray(full.steps) ? full.steps : []), "Waktu pencarian Mitra berakhir"] };
      const updates = {}; updates[`orders/${key}`] = updated; updates[`ordersByBuyer/${encodeURIComponent(full.buyerUid || order.buyerUid)}/${key}`] = updated;
      await adminDatabaseRequest("", "PATCH", env, updates);
      break;
    }
  }
}

async function getBuyerOrders(request, env) {
  const auth = await authenticate(request, env);
  if (!auth.success) return auth.response;
  const uid = auth.user.uid;
  const rows = await adminDatabaseRequest(`ordersByBuyer/${encodeURIComponent(uid)}`, "GET", env) || {};
  await expireWaitingOrders(rows, env);
  const refreshedRows = await adminDatabaseRequest(`ordersByBuyer/${encodeURIComponent(uid)}`, "GET", env) || rows;
  const orders = Object.entries(refreshedRows).map(([key, value]) => ({ ...value, _key: key })).sort((a,b) => (b.createdAt||0)-(a.createdAt||0));
  return jsonResponse({ success: true, orders });
}

async function getMitraOrders(request, env) {
  const auth = await authenticate(request, env);
  if (!auth.success) return auth.response;
  const uid = auth.user.uid;
  if (!(await hasValidMitraApproval(uid, env))) return jsonResponse({ success:false, error:"Akun Mitra belum disetujui." }, 403);
  const presence = await adminDatabaseRequest(`mitraPresence/${encodeURIComponent(uid)}`, "GET", env) || {};
  let board = await adminDatabaseRequest("orderBoard", "GET", env) || {};
  await expireWaitingOrders(board, env);
  board = await adminDatabaseRequest("orderBoard", "GET", env) || {};
  const orders = [];
  for (const [key, row] of Object.entries(board)) {
    if (!row || typeof row !== "object") continue;
    if (!row.mitraUid && row.status === "Menunggu mitra") {
      // Deliberately omit buyer identity, phone, and delivery address before claim.
      orders.push({ ...row, _key:key, address:null, buyerUid:undefined });
    } else if (row.mitraUid === uid) {
      const privateOrder = await adminDatabaseRequest(`orders/${encodeURIComponent(key)}`, "GET", env);
      if (privateOrder) orders.push({ ...privateOrder, _key:key });
    }
  }
  orders.sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));
  return jsonResponse({ success:true, state:presence.state === "online" ? "online" : "offline", orders });
}

async function mitraOrderAction(request, env, key, action) {
  const auth = await authenticate(request, env);
  if (!auth.success) return auth.response;
  const uid = auth.user.uid;
  if (!(await hasValidMitraApproval(uid, env))) return jsonResponse({ success:false, error:"Akun Mitra belum disetujui." }, 403);
  if (!/^[A-Za-z0-9_-]{8,100}$/.test(key)) return jsonResponse({ success:false, error:"ID pesanan tidak valid." }, 400);
  const presence = await adminDatabaseRequest(`mitraPresence/${encodeURIComponent(uid)}`, "GET", env) || {};
  if (presence.state !== "online") return jsonResponse({ success:false, error:"Aktifkan status Online sebelum mengelola pesanan." }, 409);
  let slotReserved = false;
  if (action === "claim") {
    const boardNow = await adminDatabaseRequest("orderBoard", "GET", env) || {};
    const activeCount = Object.values(boardNow).filter(row => row && row.mitraUid === uid && ["Diterima", "Disiapkan", "Dalam perjalanan"].includes(row.status)).length;
    if (activeCount >= 1) return jsonResponse({ success:false, error:"Selesaikan pesanan aktif terlebih dahulu. Saat ini maksimal satu pesanan aktif per Mitra." }, 409);
    slotReserved = await acquireMitraOrderSlot(uid, key, env, true);
    if (!slotReserved) return jsonResponse({ success:false, error:"Kamu sudah memiliki pesanan aktif atau sedang menerima pesanan lain." }, 409);
  }

  let nextStatus = null;
  let boardUpdated = false;
  if (action === "status") {
    let body;
    try { body = await readJson(request, 2000); } catch { return jsonResponse({success:false,error:"Permintaan tidak valid."},400); }
    nextStatus = String(body.status || "");
    if (!["Disiapkan", "Dalam perjalanan", "Selesai"].includes(nextStatus)) return jsonResponse({success:false,error:"Perubahan status tidak diizinkan."},400);
  }
  try {
    const result = await conditionalOrderBoardUpdate(key, uid, action === "claim" ? "claim" : "status", nextStatus, env);
    boardUpdated = !result.forbidden && !result.conflict;
    if (result.forbidden) { if (slotReserved) await releaseMitraOrderSlot(uid, key, env); return jsonResponse({success:false,error:"Pesanan ini bukan tanggung jawab akunmu."},403); }
    if (result.conflict) { if (slotReserved) await releaseMitraOrderSlot(uid, key, env); return jsonResponse({success:false,error:"Pesanan sudah diambil atau statusnya telah berubah."},409); }
    const order = await adminDatabaseRequest(`orders/${encodeURIComponent(key)}`, "GET", env);
    if (!order) return jsonResponse({success:false,error:"Data pesanan tidak ditemukan."},404);
    const status = action === "claim" ? "Diterima" : nextStatus;
    const eventText = action === "claim" ? "Mitra menerima pesanan" : ({Disiapkan:"Mitra mulai menyiapkan pesanan", "Dalam perjalanan":"Mitra mulai mengantar pesanan", Selesai:"Pesanan berhasil diselesaikan"})[status];
    const updatedAt = Date.now();
    const steps = Array.isArray(order.steps) ? [...order.steps] : [];
    if (steps[steps.length-1] !== eventText) steps.push(eventText);
    const changes = { mitraUid:uid, status, note:eventText + ".", updatedAt, steps };
    const updates = {};
    updates[`orders/${key}`] = { ...order, ...changes };
    updates[`ordersByBuyer/${encodeURIComponent(order.buyerUid)}/${key}`] = { ...order, ...changes };
    updates[`orderBoard/${key}`] = { ...result.board, status, mitraUid:uid, updatedAt };
    await adminDatabaseRequest("", "PATCH", env, updates);
    if (status === "Selesai") await releaseMitraOrderSlot(uid, key, env);
    return jsonResponse({success:true, order:{...order,...changes,_key:key}});
  } catch (error) {
    if (slotReserved && !boardUpdated) { try { await releaseMitraOrderSlot(uid, key, env); } catch {} }
    return jsonResponse({success:false,error:error.message || "Aksi pesanan gagal."},400);
  }
}

async function cancelBuyerOrder(request, env, key) {
  const auth = await authenticate(request, env);
  if (!auth.success) return auth.response;
  if (!/^[A-Za-z0-9_-]{8,100}$/.test(key)) return jsonResponse({success:false,error:"ID pesanan tidak valid."},400);
  const uid = auth.user.uid;
  const order = await adminDatabaseRequest(`orders/${encodeURIComponent(key)}`,"GET",env);
  if (!order) return jsonResponse({success:false,error:"Pesanan tidak ditemukan."},404);
  if (order.buyerUid !== uid) return jsonResponse({success:false,error:"Pesanan bukan milik akun ini."},403);

  // Aturan batal: (1) selama belum diterima Mitra; (2) setelah Mitra menerima tetapi
  // pesanan sudah lebih dari 10 menit dan belum mulai diantar.
  const LATE_MS = 10 * 60 * 1000;
  const age = Date.now() - Number(order.createdAt || 0);
  const waiting = order.status === "Menunggu mitra" && !order.mitraUid;
  const lateClaimed = ["Diterima", "Disiapkan"].includes(order.status) && Boolean(order.mitraUid) && age >= LATE_MS;
  if (!waiting && !lateClaimed) {
    const early = ["Diterima", "Disiapkan"].includes(order.status) && age < LATE_MS;
    return jsonResponse({success:false,error: early
      ? "Pesanan sudah diterima Mitra. Pembatalan tersedia jika lebih dari 10 menit dan belum diantar."
      : "Pesanan tidak dapat dibatalkan karena statusnya telah berubah."},409);
  }

  const token = await createAdminAccessToken(env);
  const base = env.FIREBASE_DATABASE_URL.replace(/\/+$/, "");
  const endpoint = `${base}/orderBoard/${encodeURIComponent(key)}.json`;
  for (let attempt=0; attempt<8; attempt++) {
    const read=await fetch(endpoint,{headers:{Authorization:`Bearer ${token}`,"X-Firebase-ETag":"true",Accept:"application/json"}});
    if(!read.ok) throw new Error(`Gagal membaca papan pesanan (${read.status}).`);
    const board=await read.json(); const etag=read.headers.get("ETag");
    const boardWaiting = board && board.status==="Menunggu mitra" && !board.mitraUid;
    const boardLate = board && ["Diterima","Disiapkan"].includes(board.status) && board.mitraUid && board.mitraUid===order.mitraUid && age>=LATE_MS;
    if(!board || !etag || (!boardWaiting && !boardLate)) return jsonResponse({success:false,error:"Status pesanan baru saja berubah. Muat ulang lalu coba lagi."},409);
    const previousMitra = board.mitraUid || null;
    const now = Date.now();
    board.status="Dibatalkan"; board.updatedAt=now; board.cancelledBy=uid;
    const write=await fetch(endpoint,{method:"PUT",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json","If-Match":etag},body:JSON.stringify(board)});
    if(write.status===412) continue;
    if(!write.ok) throw new Error(`Gagal memperbarui status pesanan (${write.status}).`);
    const note = previousMitra ? "Pesanan dibatalkan oleh Pembeli karena melebihi 10 menit." : "Pesanan dibatalkan oleh Pembeli sebelum Mitra menerima.";
    const updated={...order,status:"Dibatalkan",note,updatedAt:now,steps:[...(Array.isArray(order.steps)?order.steps:[]),"Pesanan dibatalkan oleh Pembeli"]};
    const updates={};updates[`orders/${key}`]=updated;updates[`ordersByBuyer/${uid}/${key}`]=updated;
    await adminDatabaseRequest("","PATCH",env,updates);
    if (previousMitra) { try { await releaseMitraOrderSlot(previousMitra, key, env); } catch {} }
    return jsonResponse({success:true,order:{...updated,_key:key}});
  }
  return jsonResponse({success:false,error:"Pesanan sedang berubah. Coba lagi."},409);
}

// ======================================================
// ROUTES
// ======================================================
async function handleRequest(request, env) {

  const url = new URL(request.url);



  const path = url.pathname;

  const method = request.method;

  // ORDER API — all buyer/Mitra reads and mutations are server-authorized.
  if (path === "/orders/mine" && method === "GET") return getBuyerOrders(request, env);
  const cancelMatch = path.match(/^\/orders\/([^/]+)\/cancel$/);
  if (cancelMatch && method === "POST") return cancelBuyerOrder(request, env, cancelMatch[1]);
  if (path === "/mitra/orders" && method === "GET") return getMitraOrders(request, env);
  const claimMatch = path.match(/^\/mitra\/orders\/([^/]+)\/claim$/);
  if (claimMatch && method === "POST") return mitraOrderAction(request, env, claimMatch[1], "claim");
  const statusMatch = path.match(/^\/mitra\/orders\/([^/]+)\/status$/);
  if (statusMatch && method === "POST") return mitraOrderAction(request, env, statusMatch[1], "status");

  // BUYER: create an order through trusted server-side validation.
  if (path === "/orders" && method === "POST") {
    return createBuyerOrder(request, env);
  }





  // ROOT
  if (path === "/" && method === "GET") {

    return jsonResponse({

      success: true,

      service: "Nitipuuy API",

      version: VERSION,

      status: "online"

    });

  }





  // HEALTH
  if (path === "/health" && method === "GET") {

    return jsonResponse({

      success: true,

      service: "Nitipuuy API",

      version: VERSION,

      status: "online",

      services: {

        firebaseProject: Boolean(env.FIREBASE_PROJECT_ID),

        firebaseDatabase: Boolean(env.FIREBASE_DATABASE_URL),

        firebaseAdminSecret: Boolean(

          env.FIREBASE_SERVICE_ACCOUNT_JSON

        ),

        adminUid: Boolean(env.ADMIN_UID),

        r2Bucket: Boolean(env.MEDIA_BUCKET),
        nikEncryptionKey: Boolean(env.MITRA_NIK_ENCRYPTION_KEY)

      }

    });

  }





  // AUTH CHECK
  if (path === "/auth/check" && method === "GET") {

    const auth = await authenticate(request, env);



    if (!auth.success) {

      return auth.response;

    }



    return jsonResponse({

      success: true,

      message: "Firebase authentication successful",

      user: {

        uid: auth.user.uid,

        email: auth.user.email,

        name: auth.user.name

      }

    });

  }





  // GET OWN PROFILE
  if (path === "/db/me" && method === "GET") {

    const auth = await authenticate(request, env);



    if (!auth.success) {

      return auth.response;

    }



    const profile = await adminDatabaseRequest(

      `users/${encodeURIComponent(auth.user.uid)}/profile`,

      "GET",

      env

    );



    return jsonResponse({

      success: true,

      user: {

        uid: auth.user.uid,

        email: auth.user.email

      },

      profile

    });

  }





  // GET OWN ROLE
  if (path === "/role/me" && method === "GET") {

    const auth = await authenticate(request, env);



    if (!auth.success) {

      return auth.response;

    }



    const role = await getUserRole(

      auth.user.uid,

      env

    );



    return jsonResponse({

      success: true,

      uid: auth.user.uid,

      role

    });

  }






  // ADMIN-ONLY DOCUMENT REPLACEMENT / DELETION. Files remain private in R2.
  if (path === "/admin/mitra-document" && (method === "POST" || method === "DELETE")) {
    const auth = await requireAdmin(request, env);
    if (!auth.success) return auth.response;
    if (!env.MEDIA_BUCKET) return jsonResponse({ success: false, error: "Private document storage unavailable" }, 503);
    const body = await readJson(request, 7_200_000);
    const uid = String(body.uid || "").trim();
    const type = String(body.type || "").trim();
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(uid) || !["ktp", "selfie", "stnk"].includes(type)) {
      return jsonResponse({ success: false, error: "Invalid document request" }, 400);
    }
    const application = await adminDatabaseRequest(`mitraApplications/${encodeURIComponent(uid)}`, "GET", env);
    if (!application || !["pending", "rejected"].includes(application.status)) {
      return jsonResponse({ success: false, error: "Dokumen hanya dapat dikelola untuk pengajuan pending atau rejected." }, 409);
    }
    if (type === "stnk" && !/^motor$/i.test(String(application.vehicleType || ""))) {
      return jsonResponse({ success: false, error: "STNK hanya diwajibkan untuk kendaraan motor." }, 409);
    }
    const fields = {
      ktp: ["ktpObjectKey", "ktpContentType"],
      selfie: ["selfieKtpObjectKey", "selfieKtpContentType"],
      stnk: ["stnkObjectKey", "stnkContentType"]
    };
    const [keyField, typeField] = fields[type];
    const oldKey = application[keyField];
    const now = Date.now();

    if (method === "DELETE") {
      const auditId = `${now}_${crypto.randomUUID()}`;
      const updates = {
        [`mitraApplications/${uid}/${keyField}`]: null,
        [`mitraApplications/${uid}/${typeField}`]: null,
        [`adminAudit/${auditId}`]: { actorUid: auth.user.uid, action: "delete_mitra_document", targetUid: uid, createdAt: now, details: { documentType: type } }
      };
      await adminDatabaseRequest("", "PATCH", env, updates);
      if (typeof oldKey === "string" && oldKey.startsWith(`mitra-documents/${uid}/`)) {
        try { await env.MEDIA_BUCKET.delete(oldKey); } catch { /* Firebase reference is already cleared; cleanup can be retried administratively. */ }
      }
      return jsonResponse({ success: true, message: "Dokumen dihapus" });
    }

    const contentType = String(body.contentType || "");
    const dataBase64 = String(body.dataBase64 || "");
    if (!["image/jpeg", "image/png"].includes(contentType) || !dataBase64 || dataBase64.length > 7_000_000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(dataBase64)) {
      return jsonResponse({ success: false, error: "File harus JPG/PNG dan maksimal 5 MB." }, 400);
    }
    let bytes;
    try {
      const binary = atob(dataBase64);
      if (binary.length < 1 || binary.length > 5 * 1024 * 1024) throw new Error("size");
      bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    } catch {
      return jsonResponse({ success: false, error: "Data file tidak valid atau melebihi 5 MB." }, 400);
    }
    const isJpeg = bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
    const isPng = bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a;
    if ((contentType === "image/jpeg" && !isJpeg) || (contentType === "image/png" && !isPng)) {
      return jsonResponse({ success: false, error: "Isi file tidak cocok dengan tipe JPG/PNG." }, 400);
    }
    const extension = contentType === "image/png" ? "png" : "jpg";
    const newKey = `mitra-documents/${uid}/admin-${type}-${crypto.randomUUID()}.${extension}`;
    await env.MEDIA_BUCKET.put(newKey, bytes, { httpMetadata: { contentType, cacheControl: "private, no-store" }, customMetadata: { uploadedBy: auth.user.uid, documentType: type, source: "admin_reverification" } });
    try {
      const auditId = `${now}_${crypto.randomUUID()}`;
      const updates = {
        [`mitraApplications/${uid}/${keyField}`]: newKey,
        [`mitraApplications/${uid}/${typeField}`]: contentType,
        [`adminAudit/${auditId}`]: { actorUid: auth.user.uid, action: "upload_or_replace_mitra_document", targetUid: uid, createdAt: now, details: { documentType: type, replacedExisting: Boolean(oldKey) } }
      };
      await adminDatabaseRequest("", "PATCH", env, updates);
    } catch (error) {
      try { await env.MEDIA_BUCKET.delete(newKey); } catch {}
      throw error;
    }
    if (typeof oldKey === "string" && oldKey.startsWith(`mitra-documents/${uid}/`) && oldKey !== newKey) {
      try { await env.MEDIA_BUCKET.delete(oldKey); } catch {}
    }
    return jsonResponse({ success: true, message: "Dokumen berhasil diunggah", documentType: type });
  }

  // MITRA APPLICATION
  // MITRA STATUS: VERIFY APPROVAL FROM ADMIN REVIEW RECORDS
  if (path === "/mitra/status" && method === "GET") {
    const auth = await authenticate(request, env);
    if (!auth.success) return auth.response;

    const uid = encodeURIComponent(auth.user.uid);

    const application = await adminDatabaseRequest(`mitraApplications/${uid}`, "GET", env);
    const validApproval = await hasValidMitraApproval(auth.user.uid, env);

    let status = "not_registered";
    if (application && ["pending", "rejected"].includes(application.status)) {
      status = application.status;
    } else if (application?.status === "approved" && validApproval) {
      status = "approved";
    } else if (application?.status === "approved") {
      status = "verification_error";
    }

    return jsonResponse({
      success: true,
      uid: auth.user.uid,
      role: validApproval ? "Mitra" : "Pembeli",
      status,
      application: safeMitraStatus(application),
      verified: validApproval
    });
  }


  // MITRA AVAILABILITY: authenticated, server-controlled online/offline state.
  if (path === "/mitra/availability" && (method === "GET" || method === "POST")) {
    const auth = await authenticate(request, env);
    if (!auth.success) return auth.response;
    const uid = auth.user.uid;
    const approved = await hasValidMitraApproval(uid, env);
    if (!approved) return jsonResponse({ success: false, error: "Akun Mitra belum disetujui." }, 403);

    const safeUid = encodeURIComponent(uid);
    const presencePath = `mitraPresence/${safeUid}`;
    const current = await adminDatabaseRequest(presencePath, "GET", env) || {};
    const board = await adminDatabaseRequest("orderBoard", "GET", env) || {};
    const activeOrder = Object.values(board).some(order => order && order.mitraUid === uid && ["Diterima", "Disiapkan", "Dalam perjalanan"].includes(order.status));

    if (method === "GET") {
      const state = activeOrder ? "online" : (current.state === "online" ? "online" : "offline");
      return jsonResponse({ success: true, state, busy: activeOrder, updatedAt: Number(current.updatedAt || 0) });
    }

    let body;
    try { body = await readJson(request, 2000); }
    catch { return jsonResponse({ success: false, error: "Format permintaan tidak valid." }, 400); }
    if (!["online", "offline"].includes(body.state)) {
      return jsonResponse({ success: false, error: "Status harus online atau offline." }, 400);
    }
    if (activeOrder && body.state === "offline") {
      return jsonResponse({ success: false, error: "Selesaikan pesanan aktif sebelum menjadi Offline.", state: "online", busy: true }, 409);
    }
    const now = Date.now();
    const presence = { state: body.state, updatedAt: now, lastSeenAt: now };
    await adminDatabaseRequest(presencePath, "PUT", env, presence);
    return jsonResponse({ success: true, state: body.state, busy: false, updatedAt: now });
  }

  // MITRA APPLICATION WITH ENCRYPTED NIK + PRIVATE KTP UPLOAD
  if (path === "/mitra/apply-secure" && method === "POST") {
    const auth = await authenticate(request, env);
    if (!auth.success) return auth.response;
    if (!env.MEDIA_BUCKET || !env.MITRA_NIK_ENCRYPTION_KEY) {
      return jsonResponse({ success: false, error: "Secure document storage is not configured" }, 503);
    }
    const role = await getUserRole(auth.user.uid, env);
    if (role !== "Pembeli") return jsonResponse({ success: false, error: "Only Pembeli can apply as Mitra" }, 403);
    const uid = auth.user.uid;
    const existing = await adminDatabaseRequest(`mitraApplications/${encodeURIComponent(uid)}`, "GET", env);
    if (existing?.status === "pending") return jsonResponse({ success: false, error: "Application is already pending" }, 409);
    if (existing?.status === "approved") return jsonResponse({ success: false, error: "Application is already approved or requires Admin verification" }, 409);
    if (existing?.status === "rejected") {
      const availableAt = Number(existing.reapplyAvailableAt || (Number(existing.rejectedAt || existing.reviewedAt || Date.now()) + 7 * 24 * 60 * 60 * 1000));
      if (Date.now() < availableAt) return jsonResponse({ success: false, error: "Masa tunggu pengajuan ulang belum berakhir", canReapply: false, reapplyAvailableAt: availableAt }, 429);
    }

    const contentLength = Number(request.headers.get("Content-Length") || 0);
    if (contentLength > 16 * 1024 * 1024) return jsonResponse({ success: false, error: "Request exceeds 16 MB limit" }, 413);
    let form;
    try { form = await request.formData(); }
    catch { return jsonResponse({ success: false, error: "Invalid multipart form data" }, 400); }

    const fullName = String(form.get("fullName") || "").trim();
    const phone = String(form.get("phone") || "").trim();
    const vehicleType = String(form.get("vehicleType") || "").trim();
    const vehicleNumber = String(form.get("vehicleNumber") || "").trim().toUpperCase();
    const address = String(form.get("address") || "").trim();
    const nik = String(form.get("nik") || "").replace(/\s/g, "");
    const consent = String(form.get("privacyConsent") || "").toLowerCase();
    const ktp = form.get("ktp");
    const selfieKtp = form.get("selfieKtp");
    const stnk = form.get("stnk");
    const requiresStnk = /^motor$/i.test(vehicleType);
    const vehiclePermission = String(form.get("vehiclePermission") || "").toLowerCase();

    if (fullName.length < 3 || fullName.length > 100 || phone.length < 8 || phone.length > 20 ||
        vehicleType.length < 2 || vehicleType.length > 50 || vehicleNumber.length < 3 || vehicleNumber.length > 20 ||
        address.length < 5 || address.length > 300 || !/^\d{16}$/.test(nik) || consent !== "true" ||
        !(ktp instanceof File) || ktp.size < 1 || ktp.size > 5 * 1024 * 1024 ||
        !(selfieKtp instanceof File) || selfieKtp.size < 1 || selfieKtp.size > 5 * 1024 * 1024 ||
        (requiresStnk && (!(stnk instanceof File) || stnk.size < 1 || stnk.size > 5 * 1024 * 1024)) || vehiclePermission !== "true") {
      return jsonResponse({ success: false, error: "Data pendaftaran tidak valid. KTP dan selfie wajib; STNK wajib khusus Mitra motor." }, 400);
    }

    const fileBytes = new Uint8Array(await ktp.arrayBuffer());
    const selfieBytes = new Uint8Array(await selfieKtp.arrayBuffer());
    const stnkBytes = requiresStnk ? new Uint8Array(await stnk.arrayBuffer()) : null;
    const detectedType = detectImageType(fileBytes);
    const selfieType = detectImageType(selfieBytes);
    const stnkType = requiresStnk ? detectImageType(stnkBytes) : null;
    if (!detectedType || !selfieType || (requiresStnk && !stnkType)) return jsonResponse({ success: false, error: "Dokumen harus berupa gambar JPEG atau PNG yang valid" }, 415);

    let encryptedNik;
    try { encryptedNik = await encryptNik(nik, env); }
    catch (error) { return jsonResponse({ success: false, error: error.message || "NIK encryption failed" }, 503); }

    const ktpKey = randomObjectKey(uid);
    const selfieKey = randomObjectKey(uid);
    const stnkKey = requiresStnk ? randomObjectKey(uid) : null;
    const uploadedKeys = [];
    try {
      const uploads = [
        [ktpKey, fileBytes, detectedType, "ktp"],
        [selfieKey, selfieBytes, selfieType, "selfie-ktp"]
      ];
      if (requiresStnk) uploads.push([stnkKey, stnkBytes, stnkType, "stnk"]);
      for (const [key, bytes, type, documentType] of uploads) {
        await env.MEDIA_BUCKET.put(key, bytes, {
          httpMetadata: { contentType: type, cacheControl: "no-store" },
          customMetadata: { ownerUid: uid, documentType, uploadedAt: String(Date.now()) }
        });
        uploadedKeys.push(key);
      }
      const application = {
        fullName, phone, vehicleType, vehicleNumber, address,
        nikEncrypted: encryptedNik,
        ktpObjectKey: ktpKey, ktpContentType: detectedType,
        selfieKtpObjectKey: selfieKey, selfieKtpContentType: selfieType,
        ...(requiresStnk ? { stnkObjectKey: stnkKey, stnkContentType: stnkType } : {}),
        vehiclePermission: true,
        status: "pending",
        submittedAt: Date.now(),
        reviewedAt: null,
        reviewedBy: null,
        rejectionReason: null,
        rejectedAt: null,
        reapplyAvailableAt: null,
        privacyConsent: true,
        privacyConsentAt: Date.now(),
        dataSchemaVersion: 3
      };
      await adminDatabaseRequest(`mitraApplications/${encodeURIComponent(uid)}`, "PUT", env, application);
    } catch (error) {
      for (const key of uploadedKeys) { try { await env.MEDIA_BUCKET.delete(key); } catch {} }
      return jsonResponse({ success: false, error: "Secure application could not be saved" }, 500);
    }
    return jsonResponse({ success: true, message: "Secure Mitra application submitted", status: "pending" }, 201);
  }

  // ADMIN-ONLY DECRYPTION OF NIK; every access is audited.
  if (path === "/admin/mitra-identity" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (!auth.success) return auth.response;
    const uid = String(url.searchParams.get("uid") || "").trim();
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(uid)) return jsonResponse({ success: false, error: "Invalid UID" }, 400);
    const application = await adminDatabaseRequest(`mitraApplications/${encodeURIComponent(uid)}`, "GET", env);
    if (!application?.nikEncrypted) return jsonResponse({ success: false, error: "Encrypted NIK not found" }, 404);
    let nik;
    try { nik = await decryptNik(application.nikEncrypted, env); }
    catch { return jsonResponse({ success: false, error: "NIK decryption failed" }, 500); }
    try { await writeAdminAudit(env, auth.user.uid, "view_mitra_nik", uid); }
    catch { return jsonResponse({ success: false, error: "Audit logging failed; identity access denied" }, 503); }
    return jsonResponse({ success: true, uid, nik });
  }

  // ADMIN-ONLY PRIVATE MITRA DOCUMENT STREAM; every access is audited.
  if (path === "/admin/mitra-document" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (!auth.success) return auth.response;
    if (!env.MEDIA_BUCKET) return jsonResponse({ success: false, error: "Private document storage unavailable" }, 503);
    const uid = String(url.searchParams.get("uid") || "").trim();
    const type = String(url.searchParams.get("type") || "ktp").trim();
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(uid)) return jsonResponse({ success: false, error: "Invalid UID" }, 400);
    const documentMap = {
      ktp: ["ktpObjectKey", "ktpContentType", "view_mitra_ktp"],
      selfie: ["selfieKtpObjectKey", "selfieKtpContentType", "view_mitra_selfie_ktp"],
      stnk: ["stnkObjectKey", "stnkContentType", "view_mitra_stnk"]
    };
    if (!Object.prototype.hasOwnProperty.call(documentMap, type)) return jsonResponse({ success: false, error: "Invalid document type" }, 400);
    const application = await adminDatabaseRequest(`mitraApplications/${encodeURIComponent(uid)}`, "GET", env);
    const [keyField, typeField, auditAction] = documentMap[type];
    const objectKey = application?.[keyField];
    if (!application || typeof objectKey !== "string" || !objectKey.startsWith(`mitra-documents/${uid}/`)) {
      return jsonResponse({ success: false, error: "Dokumen tidak ditemukan" }, 404);
    }
    const object = await env.MEDIA_BUCKET.get(objectKey);
    if (!object) return jsonResponse({ success: false, error: "Dokumen tidak ditemukan di penyimpanan privat" }, 404);
    const contentType = application[typeField] === "image/png" ? "image/png" : "image/jpeg";
    try { await writeAdminAudit(env, auth.user.uid, auditAction, uid, { documentType: type }); }
    catch { return jsonResponse({ success: false, error: "Audit logging failed; document access denied" }, 503); }
    return privateFileResponse(object, contentType);
  }

  // MITRA APPLICATION
  if (path === "/mitra/apply" && method === "POST") {

    const auth = await authenticate(request, env);



    if (!auth.success) {

      return auth.response;

    }



    const role = await getUserRole(

      auth.user.uid,

      env

    );



    if (role !== "Pembeli") {

      return jsonResponse(

        {

          success: false,

          error: "Only Pembeli can apply as Mitra"

        },

        403

      );

    }



    const existing = await adminDatabaseRequest(

      `mitraApplications/${encodeURIComponent(auth.user.uid)}`,

      "GET",

      env

    );



    if (existing?.status === "pending") {

      return jsonResponse(

        {

          success: false,

          error: "Application is already pending"

        },

        409

      );

    }



    if (existing?.status === "approved") {
      return jsonResponse(
        {
          success: false,
          error: "Application is already approved or requires Admin verification"
        },
        409
      );
    }

    const body = await readJson(request);



    const fullName =

      String(body.fullName || "").trim();



    const phone =

      String(body.phone || "").trim();



    const vehicleType =

      String(body.vehicleType || "").trim();



    const vehicleNumber =

      String(body.vehicleNumber || "").trim();



    const address =

      String(body.address || "").trim();



    if (

      fullName.length < 3 ||

      fullName.length > 100 ||

      phone.length < 8 ||

      phone.length > 20 ||

      vehicleType.length < 2 ||

      vehicleType.length > 50 ||

      vehicleNumber.length < 3 ||

      vehicleNumber.length > 20 ||

      address.length < 5 ||

      address.length > 300

    ) {

      return jsonResponse(

        {

          success: false,

          error: "Invalid application data"

        },

        400

      );

    }



    const application = {

      fullName,

      phone,

      vehicleType,

      vehicleNumber,

      address,

      status: "pending",

      submittedAt: Date.now(),

      reviewedAt: null,

      reviewedBy: null

    };



    await adminDatabaseRequest(

      `mitraApplications/${encodeURIComponent(auth.user.uid)}`,

      "PUT",

      env,

      application

    );



    return jsonResponse({

      success: true,

      message: "Mitra application submitted",

      status: "pending"

    }, 201);

  }





  // ADMIN CHECK
  if (path === "/admin/check" && method === "GET") {

    const auth = await requireAdmin(request, env);



    if (!auth.success) {

      return auth.response;

    }



    const role = await getUserRole(

      auth.user.uid,

      env

    );



    return jsonResponse({

      success: true,

      message: "Admin authentication successful",

      admin: {

        uid: auth.user.uid,

        role

      },

      firebaseAdmin: "connected"

    });

  }





  // ADMIN LIST MITRA APPLICATIONS
  if (

    path === "/admin/mitra-applications" &&

    method === "GET"

  ) {

    const auth = await requireAdmin(request, env);



    if (!auth.success) {

      return auth.response;

    }



    const applications = await adminDatabaseRequest(

      "mitraApplications",

      "GET",

      env

    );



    const result = Object.entries(applications || {})
      .map(([uid, application]) => safeAdminApplication(uid, application));



    return jsonResponse({

      success: true,

      total: result.length,

      applications: result

    });

  }





  // ADMIN REVIEW MITRA APPLICATION — supports controlled re-verification of rejected applicants.
  if (path === "/admin/mitra/review" && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (!auth.success) return auth.response;

    const body = await readJson(request);
    const uid = String(body.uid || "").trim();
    const decision = String(body.decision || "").trim();
    const rejectionReason = String(body.rejectionReason || "").trim();
    const reviewType = String(body.reviewType || "standard").trim();
    const verificationNote = String(body.verificationNote || "").trim();

    if (!/^[A-Za-z0-9_-]{1,128}$/.test(uid) ||
        !["approved", "rejected"].includes(decision) ||
        (decision === "rejected" && (rejectionReason.length < 5 || rejectionReason.length > 1000)) ||
        !["standard", "manual_reverification"].includes(reviewType)) {
      return jsonResponse({ success: false, error: "Invalid review request" }, 400);
    }
    if (uid === auth.user.uid) {
      return jsonResponse({ success: false, error: "Admin cannot review own application" }, 403);
    }

    const application = await adminDatabaseRequest(`mitraApplications/${encodeURIComponent(uid)}`, "GET", env);
    if (!application || !["pending", "rejected"].includes(application.status)) {
      return jsonResponse({ success: false, error: "Pending or rejected application not found" }, 404);
    }

    const isReverification = application.status === "rejected";
    if (isReverification && (decision !== "approved" || reviewType !== "manual_reverification")) {
      return jsonResponse({ success: false, error: "Pengajuan ditolak hanya dapat diproses melalui verifikasi ulang dan persetujuan Admin." }, 409);
    }
    if (isReverification && (verificationNote.length < 10 || verificationNote.length > 1000)) {
      return jsonResponse({ success: false, error: "Catatan verifikasi ulang wajib diisi 10–1000 karakter." }, 400);
    }
    if (!isReverification && reviewType === "manual_reverification") {
      return jsonResponse({ success: false, error: "Verifikasi ulang hanya berlaku untuk pengajuan yang berstatus rejected." }, 409);
    }

    // KTP + selfie are mandatory for every Mitra; STNK is mandatory only for motorcycles.
    if (decision === "approved") {
      const requiresStnk = /^motor$/i.test(String(application.vehicleType || ""));
      const requiredKeys = [application.ktpObjectKey, application.selfieKtpObjectKey];
      if (requiresStnk) requiredKeys.push(application.stnkObjectKey);
      if (!env.MEDIA_BUCKET || requiredKeys.some(key => typeof key !== "string" || !key.startsWith(`mitra-documents/${uid}/`))) {
        return jsonResponse({ success: false, error: requiresStnk
          ? "Verifikasi belum lengkap: KTP, selfie + KTP, dan STNK motor wajib tersedia."
          : "Verifikasi belum lengkap: KTP dan selfie + KTP wajib tersedia." }, 409);
      }
      const storedObjects = await Promise.all(requiredKeys.map(key => env.MEDIA_BUCKET.head(key)));
      if (storedObjects.some(object => !object)) {
        return jsonResponse({ success: false, error: "Salah satu dokumen wajib tidak ditemukan di penyimpanan privat. Unggah ulang dokumen sebelum menyetujui." }, 409);
      }
    }

    const now = Date.now();
    const auditId = `${now}_${crypto.randomUUID()}`;
    const historyId = `${now}_${crypto.randomUUID()}`;
    const previousStatus = application.status;
    const updates = {
      [`mitraApplications/${uid}/status`]: decision,
      [`mitraApplications/${uid}/reviewedAt`]: now,
      [`mitraApplications/${uid}/reviewedBy`]: auth.user.uid,
      [`mitraApplications/${uid}/reviewHistory/${historyId}`]: {
        previousStatus,
        newStatus: decision,
        reviewType: isReverification ? "manual_reverification" : "standard",
        reviewedAt: now,
        reviewedBy: auth.user.uid,
        ...(isReverification ? {
          verificationNote,
          previousRejectionReason: typeof application.rejectionReason === "string" ? application.rejectionReason : null,
          previousRejectedAt: Number.isFinite(application.rejectedAt) ? application.rejectedAt : null
        } : {}),
        ...(decision === "rejected" ? { rejectionReason } : {})
      },
      [`adminAudit/${auditId}`]: {
        actorUid: auth.user.uid,
        action: isReverification ? "reverify_rejected_mitra_approved" : (decision === "approved" ? "approve_mitra_application" : "reject_mitra_application"),
        targetUid: uid,
        createdAt: now,
        details: {
          previousStatus,
          newStatus: decision,
          reviewType: isReverification ? "manual_reverification" : "standard",
          ...(isReverification ? {
            verificationNote,
            previousRejectionReason: typeof application.rejectionReason === "string" ? application.rejectionReason : null
          } : {}),
          ...(decision === "rejected" ? { rejectionReason } : {})
        }
      }
    };

    if (decision === "approved") {
      updates[`users/${uid}/role`] = "Mitra";
      updates[`mitraProfiles/${uid}`] = {
        fullName: application.fullName,
        phone: application.phone,
        vehicleType: application.vehicleType,
        vehicleNumber: application.vehicleNumber,
        address: application.address,
        status: "active",
        approvedAt: now,
        approvedBy: auth.user.uid,
        ...(isReverification ? { reverifiedAt: now, reverifiedBy: auth.user.uid } : {})
      };
      // Clear the active rejection/cooldown fields while preserving the original decision in reviewHistory.
      if (isReverification) {
        updates[`mitraApplications/${uid}/rejectionReason`] = null;
        updates[`mitraApplications/${uid}/rejectedAt`] = null;
        updates[`mitraApplications/${uid}/reapplyAvailableAt`] = null;
        updates[`mitraApplications/${uid}/reverifiedAt`] = now;
        updates[`mitraApplications/${uid}/reverifiedBy`] = auth.user.uid;
      }
    } else {
      updates[`mitraApplications/${uid}/rejectionReason`] = rejectionReason;
      updates[`mitraApplications/${uid}/rejectedAt`] = now;
      updates[`mitraApplications/${uid}/reapplyAvailableAt`] = now + 7 * 24 * 60 * 60 * 1000;
    }

    await adminDatabaseRequest("", "PATCH", env, updates);
    return jsonResponse({
      success: true,
      message: isReverification ? "Rejected Mitra application manually re-verified and approved" : (decision === "approved" ? "Mitra application approved" : "Mitra application rejected"),
      uid,
      previousStatus,
      status: decision,
      reviewType: isReverification ? "manual_reverification" : "standard",
      reviewedAt: now
    });
  }


  // NOT FOUND
  return jsonResponse(

    {

      success: false,

      error: "Endpoint not found"

    },

    404

  );

}





// ======================================================
// WORKER ENTRY
// ======================================================
export default {

  async fetch(request, env) {

    const headers = corsHeaders(request);



    if (!isAllowedOrigin(request)) {

      return jsonResponse(

        {

          success: false,

          error: "Origin not allowed"

        },

        403,

        headers

      );

    }



    if (request.method === "OPTIONS") {

      return new Response(null, {

        status: 204,

        headers

      });

    }



    try {

      const response = await handleRequest(

        request,

        env

      );



      const finalHeaders = new Headers(

        response.headers

      );



      for (const [key, value] of Object.entries(headers)) {

        finalHeaders.set(key, value);

      }



      return new Response(response.body, {

        status: response.status,

        statusText: response.statusText,

        headers: finalHeaders

      });



    } catch (error) {

      return jsonResponse(

        {

          success: false,

          error: "Internal server error",

          details: error.message

        },

        500,

        headers

      );

    }

  }

};