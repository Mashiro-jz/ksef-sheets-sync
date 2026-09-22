import { NextResponse } from "next/server";
import { google } from "googleapis";
import crypto from "crypto";

// KSeF API 2.0 - produkcja
const KSEF_BASE_URL = "https://api.ksef.mf.gov.pl/api/v2";

// ---------------------------------------------------------
// Pomocnicze: parsowanie odpowiedzi KSeF
// ---------------------------------------------------------
async function parseKsefResponse(response, operationName) {
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(
      `${operationName}: KSeF zwrócił niepoprawny JSON/HTML. HTTP ${response.status}: ${text.substring(0, 300)}`,
    );
  }
  if (!response.ok) {
    const exceptionDetails = data?.exception?.exceptionDetailList
      ?.map((item) => {
        const details = item.details?.length
          ? ` (${item.details.join("; ")})`
          : "";
        return `${item.exceptionCode}: ${item.exceptionDescription}${details}`;
      })
      .join(" | ");
    const message =
      exceptionDetails ||
      data?.detail ||
      data?.title ||
      data?.description ||
      text ||
      response.statusText;
    throw new Error(`${operationName}: ${message} [HTTP ${response.status}]`);
  }
  return data;
}

// ---------------------------------------------------------
// Pomocnicze: opóźnienie
// ---------------------------------------------------------
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------
// KSeF - uwierzytelnienie tokenem KSeF
// ---------------------------------------------------------
async function authenticateKsef(nipFirmy) {
  const ksefToken = process.env.KSEF_TOKEN;
  if (!ksefToken) throw new Error("Brak zmiennej środowiskowej KSEF_TOKEN.");

  // 1. Challenge
  const challengeRes = await fetch(`${KSEF_BASE_URL}/auth/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Error-Format": "problem-details",
    },
    body: JSON.stringify({
      contextIdentifier: { type: "Nip", value: nipFirmy }, // poprawne dla KSeF 2.0
    }),
  });

  const challengeData = await parseKsefResponse(challengeRes, "KSeF Challenge");
  const challenge = challengeData.challenge;
  const timestampMs = challengeData.timestampMs;

  if (!challenge || !timestampMs)
    throw new Error("KSeF Challenge: brak pola challenge lub timestampMs.");

  // 2. Pobranie aktualnego certyfikatu MF
  const certRes = await fetch(
    `${KSEF_BASE_URL}/security/public-key-certificates`,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        "X-Error-Format": "problem-details",
      },
    },
  );

  const certsJson = await parseKsefResponse(
    certRes,
    "KSeF Public Key Certificates",
  );
  const cert = certsJson.find(
    (item) =>
      Array.isArray(item.usage) && item.usage.includes("KsefTokenEncryption"),
  );

  if (!cert || !cert.certificate || !cert.publicKeyId) {
    throw new Error(
      "KSeF: nie znaleziono odpowiedniego certyfikatu (KsefTokenEncryption).",
    );
  }

  const base64DerCert = cert.certificate;
  const publicKeyId = cert.publicKeyId;
  const certificateLines = base64DerCert.match(/.{1,64}/g)?.join("\n");
  const publicKeyPem = `-----BEGIN CERTIFICATE-----\n${certificateLines}\n-----END CERTIFICATE-----\n`;

  // 3. Zbudowanie wiadomości do szyfrowania i RSA-OAEP
  const authMessage = `${ksefToken}|${timestampMs}`;
  const encryptedToken = crypto
    .publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(authMessage, "utf8"),
    )
    .toString("base64");

  // 4. Rozpoczęcie uwierzytelniania tokenem
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

  if (!referenceNumber || !authenticationToken)
    throw new Error("KSeF Auth: brak danych uwierzytelniania.");

  // 5. Czekamy na zakończenie uwierzytelniania
  let authStatus = null;
  for (let attempt = 1; attempt <= 20; attempt++) {
    await sleep(500);
    const statusRes = await fetch(
      `${KSEF_BASE_URL}/auth/${encodeURIComponent(referenceNumber)}`,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${authenticationToken}`,
          "X-Error-Format": "problem-details",
        },
      },
    );

    authStatus = await parseKsefResponse(statusRes, "KSeF Auth Status");
    if (authStatus?.status?.code === 200) break;
    if (authStatus?.status?.code === 100) continue;

    throw new Error(
      `KSeF Auth Status: Kod ${authStatus?.status?.code || "Nieznany"}.`,
    );
  }

  if (authStatus?.status?.code !== 200)
    throw new Error("KSeF Auth Status: Timeout.");

  // 6. Pobranie właściwego accessToken
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

// ---------------------------------------------------------
// POST /api/sync
// ---------------------------------------------------------
export async function POST(request) {
  try {
    const body = await request.json();
    const { secretKey, sheetId } = body;

    if (secretKey !== process.env.API_SECRET_KEY) {
      return NextResponse.json(
        { error: "Odmowa dostępu. Nieprawidłowy klucz." },
        { status: 401 },
      );
    }

    const nipFirmy = (process.env.NIP_FIRMY || "").replace(/\D/g, "");
    if (nipFirmy.length !== 10) throw new Error(`NIP_FIRMY musi mieć 10 cyfr.`);

    const googlePrivateKey = (process.env.GOOGLE_PRIVATE_KEY || "").replace(
      /\\n/g,
      "\n",
    );
    const googleServiceAccountEmail = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
    if (!googleServiceAccountEmail || !googlePrivateKey)
      throw new Error("Brak konfiguracji Google (Email lub Klucz).");

    const auth = new google.auth.GoogleAuth({
      credentials: {
        client_email: googleServiceAccountEmail,
        private_key: googlePrivateKey,
      },
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });
    const sheets = google.sheets({ version: "v4", auth });

    // 1. Pobranie historii z kolumny H
    let existingInvoiceNumbers = new Set();
    try {
      const existingData = await sheets.spreadsheets.values.get({
        spreadsheetId: sheetId,
        range: "Arkusz1!H:H",
      });
      const rows = existingData.data.values;
      if (rows && rows.length > 0) {
        existingInvoiceNumbers = new Set(
          rows
            .map((row) => row[0])
            .filter(Boolean)
            .map((v) => String(v).trim()),
        );
      }
    } catch (e) {
      console.warn("Nie udało się pobrać historii:", e.message);
    }

    // 2. Uwierzytelnienie
    const accessToken = await authenticateKsef(nipFirmy);

    // ----------------------------------------------------------------------------------
    // ZMIANA: ZAWSZE POBIERAMY OD 1-GO DNIA POPRZEDNIEGO MIESIĄCA
    // ----------------------------------------------------------------------------------
    const dzisiaj = new Date();

    // 1. dzień poprzedniego miesiąca, godzina 00:00:00
    const poczatekPoprzedniegoMiesiaca = new Date(
      dzisiaj.getFullYear(),
      dzisiaj.getMonth() - 1,
      1,
      0,
      0,
      0,
      0,
    );
    const poczatekOkresuISO = poczatekPoprzedniegoMiesiaca.toISOString();

    // Ostatni dzień bieżącego miesiąca, godzina 23:59:59 (np. 30 września, 31 października)
    // Trik: wpisanie '0' jako dnia przeskakuje na ostatni dzień danego miesiąca
    const koniecObecnegoMiesiaca = new Date(
      dzisiaj.getFullYear(),
      dzisiaj.getMonth() + 1,
      0,
      23,
      59,
      59,
      999,
    );
    const terazISO = koniecObecnegoMiesiaca.toISOString();

    // 3. Pobranie faktur
    const allInvoices = [];
    let pageOffset = 0;
    let hasMore = true;

    while (hasMore) {
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
            from: poczatekOkresuISO,
            to: terazISO,
          },
        }),
      });

      const syncData = await parseKsefResponse(
        syncRes,
        "KSeF Invoice Metadata",
      );
      const invoices = Array.isArray(syncData.invoices)
        ? syncData.invoices
        : [];
      allInvoices.push(...invoices);

      hasMore = syncData.hasMore === true;
      if (hasMore) pageOffset += 250;
    }

    // 4. Formatowanie nowych faktur i deduplikacja (Mapowanie od Kolumny B)
    const newInvoicesToAppend = [];
    const nazwyMiesiecy = [
      "01 (STY)",
      "02 (LUT)",
      "03 (MAR)",
      "04 (KWI)",
      "05 (MAJ)",
      "06 (CZE)",
      "07 (LIP)",
      "08 (SIE)",
      "09 (WRZ)",
      "10 (PAŹ)",
      "11 (LIS)",
      "12 (GRU)",
    ];

    for (const inv of allInvoices) {
      const invoiceNumber = inv.invoiceNumber
        ? String(inv.invoiceNumber).trim()
        : "";
      if (!invoiceNumber || existingInvoiceNumbers.has(invoiceNumber)) continue;

      // Miesiąc (na podstawie issueDate)
      const dataFaktury = inv.issueDate || "";
      let miesiacFormat = "";
      if (dataFaktury.length >= 7) {
        const miesiacNum = parseInt(dataFaktury.substring(5, 7), 10);
        if (!isNaN(miesiacNum) && miesiacNum >= 1 && miesiacNum <= 12) {
          miesiacFormat = nazwyMiesiecy[miesiacNum - 1];
        }
      }

      // Kwota
      const grossAmount =
        typeof inv.grossAmount === "number"
          ? inv.grossAmount
          : parseFloat(inv.grossAmount || 0);
      const kwotaBrutto = Number.isFinite(grossAmount)
        ? grossAmount.toFixed(2).replace(".", ",")
        : "0,00";

      // Kontrahent
      const nazwaWydatku = inv.seller?.name || inv.seller?.nip || "Brak nazwy";

      // Pomijamy kolumnę A w JSON-ie i wrzucamy dane prosto od kolumny B.
      // Apostrof ' przed datą wymusza format tekstowy.
      newInvoicesToAppend.push([
        miesiacFormat, // B: miesiac
        `'${dataFaktury}`, // C: data
        "", // D: Konto kosztowe
        "", // E: Subkonto
        nazwaWydatku, // F: Nazwa wydatku
        kwotaBrutto, // G: Kwota brutto
        invoiceNumber, // H: numer faktury
        "przelew", // I: sposób płatności
        "Faktura jest", // J: Faktura / paragon
        "",
        "",
        "", // K, L, M
      ]);

      existingInvoiceNumbers.add(invoiceNumber);
    }

    // 5. Zapis w Google Sheets (od kolumny B)
    if (newInvoicesToAppend.length > 0) {
      await sheets.spreadsheets.values.append({
        spreadsheetId: sheetId,
        range: "Arkusz1!B:M",
        valueInputOption: "USER_ENTERED",
        insertDataOption: "INSERT_ROWS",
        requestBody: { values: newInvoicesToAppend },
      });
    }

    return NextResponse.json({
      success: true,
      added: newInvoicesToAppend.length,
      fetched: allInvoices.length,
      message: `Znaleziono faktur (od ubiegłego miesiąca): ${allInvoices.length}. Dodano nowych: ${newInvoicesToAppend.length}.`,
    });
  } catch (error) {
    console.error("Wystąpił błąd krytyczny:", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
