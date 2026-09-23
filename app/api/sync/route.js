import { NextResponse } from "next/server";
import { google } from "googleapis";
import crypto from "crypto";

// =========================================================
// KSeF API 2.0 - produkcja
// =========================================================
const KSEF_BASE_URL = "https://api.ksef.mf.gov.pl/v2";

// =========================================================
// Pomocnicze: parsowanie odpowiedzi KSeF
// =========================================================
async function parseKsefResponse(response, operationName) {
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`${operationName}: KSeF zwrócił niepoprawny JSON/HTML. HTTP ${response.status}: ${text.substring(0, 500)}`);
  }
  if (!response.ok) {
    const exceptionDetails = data?.exception?.exceptionDetailList
      ?.map((item) => {
        const details = item.details?.length ? ` (${item.details.join("; ")})` : "";
        return `${item.exceptionCode}: ${item.exceptionDescription}${details}`;
      })
      .join(" | ");
    const message = exceptionDetails || data?.detail || data?.title || data?.description || text || response.statusText;
    throw new Error(`${operationName}: ${message} [HTTP ${response.status}]`);
  }
  return data;
}

// =========================================================
// Pomocnicze: opóźnienie
// =========================================================
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// =========================================================
// Normalizacja tekstu i kwoty do deduplikacji
// =========================================================
function normalizeText(value) {
  return String(value ?? "").trim().toLowerCase().replace(/^'/, "");
}

function normalizeAmount(value) {
  if (value === null || value === undefined || value === "") return "";
  const normalized = String(value).trim().replace(",", ".");
  const number = Number(normalized);
  if (!Number.isFinite(number)) return normalized;
  return number.toFixed(2);
}

function createLegacyKey({ invoiceNumber, issueDate, sellerName, grossAmount }) {
  return [
    normalizeText(invoiceNumber),
    normalizeText(issueDate),
    normalizeText(sellerName),
    normalizeAmount(grossAmount),
  ].join("|");
}

// =========================================================
// KSeF - uwierzytelnienie tokenem KSeF
// =========================================================
async function authenticateKsef(nipFirmy) {
  const ksefToken = process.env.KSEF_TOKEN;
  if (!ksefToken) throw new Error("Brak zmiennej środowiskowej KSEF_TOKEN.");

  const challengeRes = await fetch(`${KSEF_BASE_URL}/auth/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Error-Format": "problem-details",
    },
    body: JSON.stringify({
      contextIdentifier: { type: "Nip", value: nipFirmy },
    }),
  });

  const challengeData = await parseKsefResponse(challengeRes, "KSeF Challenge");
  const challenge = challengeData.challenge;
  const timestampMs = challengeData.timestampMs;

  if (!challenge || !timestampMs) throw new Error("KSeF Challenge: brak pola challenge lub timestampMs.");

  const certRes = await fetch(`${KSEF_BASE_URL}/security/public-key-certificates`, {
    method: "GET",
    headers: {
      Accept: "application/json",
      "X-Error-Format": "problem-details",
    },
  });

  const certsJson = await parseKsefResponse(certRes, "KSeF Public Key Certificates");
  const cert = certsJson.find((item) => Array.isArray(item.usage) && item.usage.includes("KsefTokenEncryption"));

  if (!cert || !cert.certificate || !cert.publicKeyId) {
    throw new Error("KSeF: nie znaleziono odpowiedniego certyfikatu (KsefTokenEncryption).");
  }

  const base64DerCert = cert.certificate;
  const publicKeyId = cert.publicKeyId;
  const certificateLines = base64DerCert.match(/.{1,64}/g)?.join("\n");
  const publicKeyPem = `-----BEGIN CERTIFICATE-----\n${certificateLines}\n-----END CERTIFICATE-----`;

  const authMessage = `${ksefToken}|${timestampMs}`;
  const encryptedToken = crypto
    .publicEncrypt(
      { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      Buffer.from(authMessage, "utf8")
    ).toString("base64");

  const authKsefRes = await fetch(`${KSEF_BASE_URL}/auth/ksef-token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Error-Format": "problem-details",
    },
    body: JSON.stringify({
      challenge,
      contextIdentifier: { type: "Nip", value: nipFirmy },
      encryptedToken,
      publicKeyId,
    }),
  });

  const authData = await parseKsefResponse(authKsefRes, "KSeF Auth");
  const referenceNumber = authData.referenceNumber;
  const authenticationToken = authData.authenticationToken?.token;

  if (!referenceNumber || !authenticationToken) throw new Error("KSeF Auth: brak danych uwierzytelniania.");

  let authStatus = null;
  for (let attempt = 1; attempt <= 20; attempt++) {
    await sleep(500);
    const statusRes = await fetch(`${KSEF_BASE_URL}/auth/${encodeURIComponent(referenceNumber)}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${authenticationToken}`,
        "X-Error-Format": "problem-details",
      },
    });

    authStatus = await parseKsefResponse(statusRes, "KSeF Auth Status");
    if (authStatus?.status?.code === 200) break;
    if (authStatus?.status?.code === 100) continue;
    throw new Error(`KSeF Auth Status: Kod ${authStatus?.status?.code || "Nieznany"}.`);
  }

  if (authStatus?.status?.code !== 200) throw new Error("KSeF Auth Status: Timeout.");

  const redeemRes = await fetch(`${KSEF_BASE_URL}/auth/token/redeem`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${authenticationToken}`,
      "X-Error-Format": "problem-details",
    },
  });

  const redeemData = await parseKsefResponse(redeemRes, "KSeF Token Redeem");
  const accessToken = redeemData?.accessToken?.token;
  if (!accessToken) throw new Error("KSeF Token Redeem: brak tokena.");

  return accessToken;
}

// =========================================================
// POST /api/sync
// =========================================================
export async function POST(request) {
  try {
    const body = await request.json();
    const { secretKey, sheetId } = body;

    if (secretKey !== process.env.API_SECRET_KEY) {
      return NextResponse.json({ error: "Odmowa dostępu. Nieprawidłowy klucz." }, { status: 401 });
    }

    if (!sheetId) {
      return NextResponse.json({ error: "Brak sheetId." }, { status: 400 });
    }

    const nipFirmy = (process.env.NIP_FIRMY || "").replace(/\D/g, "");
    if (nipFirmy.length !== 10) throw new Error("NIP_FIRMY musi mieć 10 cyfr.");

    const googlePrivateKey = (process.env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, "\n");
    const googleServiceAccountEmail = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
    if (!googleServiceAccountEmail || !googlePrivateKey) throw new Error("Brak konfiguracji Google.");

    const auth = new google.auth.GoogleAuth({
      credentials: { client_email: googleServiceAccountEmail, private_key: googlePrivateKey },
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });
    const sheets = google.sheets({ version: "v4", auth });

    // =====================================================
    // 5. Pobranie istniejących danych do deduplikacji
    // Pobieramy tylko kolumny od C (Data) do H (Numer faktury)
    // =====================================================
    const existingLegacyKeys = new Set();
    try {
      const existingData = await sheets.spreadsheets.values.get({
        spreadsheetId: sheetId,
        range: "Arkusz1!C:H", 
      });

      const rows = existingData.data.values || [];
      for (const row of rows) {
        // row[0]=C(Data), row[3]=F(Kontrahent), row[4]=G(Kwota), row[5]=H(Numer)
        const issueDate = String(row[0] || "").trim().replace(/^'/, "");
        const sellerName = String(row[3] || "").trim();
        const grossAmount = row[4];
        const invoiceNumber = String(row[5] || "").trim();

        if (invoiceNumber && issueDate) {
          const legacyKey = createLegacyKey({ invoiceNumber, issueDate, sellerName, grossAmount });
          existingLegacyKeys.add(legacyKey);
        }
      }
    } catch (e) {
      console.warn("Nie udało się pobrać historii arkusza:", e.message);
    }

    // =====================================================
    // 6. Uwierzytelnienie KSeF
    // =====================================================
    const accessToken = await authenticateKsef(nipFirmy);

    // =====================================================
    // 7. Pobieranie od 1. dnia poprzedniego miesiąca
    // =====================================================
    const teraz = new Date();
    const poczatekOkresu = new Date(teraz.getFullYear(), teraz.getMonth() - 1, 1, 0, 0, 0, 0);

    const fromISO = poczatekOkresu.toISOString();
    const toISO = teraz.toISOString();

    // =====================================================
    // 8. Pobieranie faktur z KSeF
    // =====================================================
    const allInvoices = [];
    let pageOffset = 0;
    let hasMore = true;
    let safetyCounter = 0;

    while (hasMore) {
      safetyCounter++;
      if (safetyCounter > 1000) throw new Error("KSeF: przekroczono limit stron synchronizacji.");

      const url = `${KSEF_BASE_URL}/invoices/query/metadata?pageSize=250&pageOffset=${pageOffset}&sortOrder=Asc`;
      const syncRes = await fetch(url, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
          "X-Error-Format": "problem-details",
        },
        body: JSON.stringify({
          subjectType: "Subject2",
          dateRange: {
            dateType: "Invoicing",
            from: fromISO,
            to: toISO,
          },
        }),
      });

      const syncData = await parseKsefResponse(syncRes, "KSeF Invoice Metadata");
      const invoices = Array.isArray(syncData.invoices) ? syncData.invoices : [];
      allInvoices.push(...invoices);

      hasMore = syncData.hasMore === true;
      if (hasMore) pageOffset += 250;
    }

    // =====================================================
    // 9. Przygotowanie danych (Tylko kolumny B do J)
    // =====================================================
    const newInvoicesToAppend = [];
    const nazwyMiesiecy = [
      "01 (STY)", "02 (LUT)", "03 (MAR)", "04 (KWI)", "05 (MAJ)", "06 (CZE)",
      "07 (LIP)", "08 (SIE)", "09 (WRZ)", "10 (PAŹ)", "11 (LIS)", "12 (GRU)",
    ];
    const seenLegacyKeys = new Set();

    for (const inv of allInvoices) {
      const invoiceNumber = inv.invoiceNumber ? String(inv.invoiceNumber).trim() : "";
      const issueDate = inv.issueDate ? String(inv.issueDate).trim() : "";
      const sellerName = inv.seller?.name || inv.seller?.nip || "Brak nazwy";
      
      if (!invoiceNumber) continue;

      const grossAmount = typeof inv.grossAmount === "number" ? inv.grossAmount : parseFloat(inv.grossAmount || 0);
      const legacyKey = createLegacyKey({ invoiceNumber, issueDate, sellerName, grossAmount });

      if (existingLegacyKeys.has(legacyKey) || seenLegacyKeys.has(legacyKey)) {
        continue;
      }

      let miesiacFormat = "";
      if (issueDate.length >= 7) {
        const miesiacNum = parseInt(issueDate.substring(5, 7), 10);
        if (!isNaN(miesiacNum) && miesiacNum >= 1 && miesiacNum <= 12) {
          miesiacFormat = nazwyMiesiecy[miesiacNum - 1];
        }
      }

      const kwotaBrutto = Number.isFinite(grossAmount) ? grossAmount.toFixed(2).replace(".", ",") : "0,00";

      newInvoicesToAppend.push([
        miesiacFormat,        // B: miesiąc
        `'${issueDate}`,      // C: data
        "",                   // D: konto kosztowe
        "",                   // E: subkonto
        sellerName,           // F: kontrahent
        kwotaBrutto,          // G: kwota
        invoiceNumber,        // H: nr faktury
        "przelew",            // I: płatność
        "Faktura jest",       // J: dokument
      ]);

      seenLegacyKeys.add(legacyKey);
    }

    // =====================================================
    // 10. Zapis do Google Sheets (B:J)
    // =====================================================
    if (newInvoicesToAppend.length > 0) {
      await sheets.spreadsheets.values.append({
        spreadsheetId: sheetId,
        range: "Arkusz1!B:J",
        valueInputOption: "USER_ENTERED",
        insertDataOption: "INSERT_ROWS",
        requestBody: { values: newInvoicesToAppend },
      });
    }

    return NextResponse.json({
      success: true,
      added: newInvoicesToAppend.length,
      fetched: allInvoices.length,
      message: `Znaleziono faktur w KSeF: ${allInvoices.length}. Dodano nowych: ${newInvoicesToAppend.length}.`,
    });
  } catch (error) {
    console.error("Wystąpił błąd krytyczny:", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 }
    );
  }
}