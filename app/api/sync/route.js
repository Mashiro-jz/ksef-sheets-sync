import { NextResponse } from "next/server";
import { google } from "googleapis";
import crypto from "crypto";

// KSeF API 2.0 - produkcja
const KSEF_BASE_URL = "https://api.ksef.mf.gov.pl/v2";

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
      `${operationName}: KSeF zwrócił niepoprawny JSON/HTML. ` +
        `HTTP ${response.status}: ${text.substring(0, 300)}`,
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

  if (!ksefToken) {
    throw new Error("Brak zmiennej środowiskowej KSEF_TOKEN.");
  }

  // -------------------------------------------------------
  // 1. Challenge
  // -------------------------------------------------------

  const challengeRes = await fetch(`${KSEF_BASE_URL}/auth/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Error-Format": "problem-details",
    },
    body: JSON.stringify({
      contextIdentifier: {
        type: "Nip",
        value: nipFirmy,
      },
    }),
  });

  const challengeData = await parseKsefResponse(challengeRes, "KSeF Challenge");

  const challenge = challengeData.challenge;
  const timestampMs = challengeData.timestampMs;

  if (!challenge) {
    throw new Error("KSeF Challenge: brak pola challenge.");
  }

  if (!timestampMs) {
    throw new Error("KSeF Challenge: brak pola timestampMs.");
  }

  // -------------------------------------------------------
  // 2. Pobranie aktualnego certyfikatu MF
  // -------------------------------------------------------

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

  if (!Array.isArray(certsJson)) {
    throw new Error(
      "KSeF Public Key Certificates: odpowiedź nie jest tablicą.",
    );
  }

  // Szukamy certyfikatu przeznaczonego do szyfrowania
  // tokenów KSeF.
  const cert = certsJson.find(
    (item) =>
      Array.isArray(item.usage) && item.usage.includes("KsefTokenEncryption"),
  );

  if (!cert) {
    throw new Error(
      "KSeF: nie znaleziono certyfikatu z usage = KsefTokenEncryption.",
    );
  }

  if (!cert.certificate) {
    throw new Error(
      "KSeF: znaleziony certyfikat nie posiada pola certificate.",
    );
  }

  if (!cert.publicKeyId) {
    throw new Error(
      "KSeF: znaleziony certyfikat nie posiada pola publicKeyId.",
    );
  }

  const base64DerCert = cert.certificate;
  const publicKeyId = cert.publicKeyId;

  const certificateLines = base64DerCert.match(/.{1,64}/g)?.join("\n");

  if (!certificateLines) {
    throw new Error("KSeF: nie udało się przygotować certyfikatu PEM.");
  }

  const publicKeyPem =
    `-----BEGIN CERTIFICATE-----\n` +
    `${certificateLines}\n` +
    `-----END CERTIFICATE-----\n`;

  // -------------------------------------------------------
  // 3. Zbudowanie wiadomości do szyfrowania
  //
  // KSeF wymaga:
  //
  // KSEF_TOKEN|timestampMs
  //
  // -------------------------------------------------------

  const authMessage = `${ksefToken}|${timestampMs}`;

  // -------------------------------------------------------
  // 4. RSA-OAEP + SHA-256
  // -------------------------------------------------------

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

  // -------------------------------------------------------
  // 5. Rozpoczęcie uwierzytelniania tokenem
  // -------------------------------------------------------

  const authKsefRes = await fetch(`${KSEF_BASE_URL}/auth/ksef-token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Error-Format": "problem-details",
    },
    body: JSON.stringify({
      challenge,
      contextIdentifier: {
        type: "Nip",
        value: nipFirmy,
      },
      encryptedToken,
      publicKeyId,
    }),
  });

  const authData = await parseKsefResponse(authKsefRes, "KSeF Auth");

  const referenceNumber = authData.referenceNumber;
  const authenticationToken = authData.authenticationToken?.token;

  if (!referenceNumber) {
    throw new Error("KSeF Auth: brak referenceNumber w odpowiedzi.");
  }

  if (!authenticationToken) {
    throw new Error("KSeF Auth: brak authenticationToken.token w odpowiedzi.");
  }

  // -------------------------------------------------------
  // 6. Czekamy na zakończenie uwierzytelniania
  //
  // GET /auth/{referenceNumber}
  //
  // 100 = w toku
  // 200 = sukces
  // -------------------------------------------------------

  const maxAttempts = 20;
  const delayMs = 500;

  let authStatus = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    await sleep(delayMs);

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

    const statusCode = authStatus?.status?.code;

    // Sukces
    if (statusCode === 200) {
      break;
    }

    // Nadal trwa
    if (statusCode === 100) {
      continue;
    }

    // Każdy inny status oznacza problem
    const details = authStatus?.status?.details?.length
      ? ` Szczegóły: ${authStatus.status.details.join("; ")}`
      : "";

    throw new Error(
      `KSeF Auth Status: uwierzytelnianie nie powiodło się. ` +
        `Kod ${statusCode}: ${authStatus?.status?.description || "Brak opisu"}.` +
        details,
    );
  }

  if (authStatus?.status?.code !== 200) {
    throw new Error(
      "KSeF Auth Status: przekroczono czas oczekiwania na zakończenie uwierzytelniania.",
    );
  }

  // -------------------------------------------------------
  // 7. Pobranie właściwego accessToken
  //
  // POST /auth/token/redeem
  // -------------------------------------------------------

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

  if (!accessToken) {
    throw new Error("KSeF Token Redeem: brak accessToken.token w odpowiedzi.");
  }

  return accessToken;
}

// ---------------------------------------------------------
// POST /api/sync
// ---------------------------------------------------------

export async function POST(request) {
  try {
    // -------------------------------------------------------
    // 0. Dane wejściowe
    // -------------------------------------------------------

    const body = await request.json();

    const { secretKey, sheetId } = body;

    if (!secretKey) {
      return NextResponse.json(
        {
          error: "Brak secretKey.",
        },
        { status: 400 },
      );
    }

    if (!sheetId) {
      return NextResponse.json(
        {
          error: "Brak sheetId.",
        },
        { status: 400 },
      );
    }

    // -------------------------------------------------------
    // 1. Sprawdzenie API_SECRET_KEY
    // -------------------------------------------------------

    if (secretKey !== process.env.API_SECRET_KEY) {
      return NextResponse.json(
        {
          error: "Odmowa dostępu. Nieprawidłowy klucz.",
        },
        { status: 401 },
      );
    }

    // -------------------------------------------------------
    // 2. Konfiguracja firmy
    // -------------------------------------------------------

    const nipFirmy = (process.env.NIP_FIRMY || "").replace(/\D/g, "");

    if (!nipFirmy) {
      throw new Error("Brak lub nieprawidłowy NIP_FIRMY.");
    }

    if (nipFirmy.length !== 10) {
      throw new Error(
        `NIP_FIRMY musi mieć 10 cyfr. Otrzymano: ${nipFirmy.length}.`,
      );
    }

    // -------------------------------------------------------
    // 3. Google Sheets
    // -------------------------------------------------------

    const googlePrivateKey = (process.env.GOOGLE_PRIVATE_KEY || "").replace(
      /\\n/g,
      "\n",
    );

    const googleServiceAccountEmail = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;

    if (!googleServiceAccountEmail) {
      throw new Error("Brak GOOGLE_SERVICE_ACCOUNT_EMAIL.");
    }

    if (!googlePrivateKey) {
      throw new Error("Brak GOOGLE_PRIVATE_KEY.");
    }

    const auth = new google.auth.GoogleAuth({
      credentials: {
        client_email: googleServiceAccountEmail,
        private_key: googlePrivateKey,
      },
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    const sheets = google.sheets({
      version: "v4",
      auth,
    });

    // -------------------------------------------------------
    // 4. Pobranie istniejących numerów faktur
    //
    // Kolumna H = numer faktury
    // -------------------------------------------------------

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
            .map((value) => String(value).trim()),
        );
      }
    } catch (e) {
      console.warn("Nie udało się pobrać historii faktur:", e.message);
    }

    // -------------------------------------------------------
    // 5. Uwierzytelnienie KSeF
    // -------------------------------------------------------

    console.log(`Rozpoczynam uwierzytelnianie KSeF dla NIP: ${nipFirmy}`);

    const accessToken = await authenticateKsef(nipFirmy);

    console.log("Uwierzytelnianie KSeF zakończone sukcesem.");

    // -------------------------------------------------------
    // 6. Zakres dat
    //
    // Pobieramy faktury kosztowe z bieżącego miesiąca.
    //
    // Subject2 = nabywca
    //
    // Invoicing = data przyjęcia faktury przez KSeF
    // -------------------------------------------------------

    const dzisiaj = new Date();

    const poczatekMiesiaca = new Date(
      dzisiaj.getFullYear(),
      dzisiaj.getMonth(),
      1,
      0,
      0,
      0,
      0,
    );

    const poczatekMiesiacaISO = poczatekMiesiaca.toISOString();

    const terazISO = dzisiaj.toISOString();

    // -------------------------------------------------------
    // 7. Pobranie metadanych faktur
    //
    // POST /invoices/query/metadata
    //
    // pageSize max = 250
    // -------------------------------------------------------

    const allInvoices = [];

    let pageOffset = 0;
    let hasMore = true;

    while (hasMore) {
      const url =
        `${KSEF_BASE_URL}/invoices/query/metadata` +
        `?pageSize=250` +
        `&pageOffset=${pageOffset}` +
        `&sortOrder=Asc`;

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
            from: poczatekMiesiacaISO,
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

      if (hasMore) {
        pageOffset += 250;
      }
    }

    console.log(`KSeF: pobrano ${allInvoices.length} faktur.`);

    // -------------------------------------------------------
    // 8. Przygotowanie nowych faktur do Google Sheets
    // -------------------------------------------------------

    const newInvoicesToAppend = [];
    const nazwyMiesiecy = ["01 (STY)", "02 (LUT)", "03 (MAR)", "04 (KWI)", "05 (MAJ)", "06 (CZE)", "07 (LIP)", "08 (SIE)", "09 (WRZ)", "10 (PAŹ)", "11 (LIS)", "12 (GRU)"];

    for (const inv of allInvoices) {
      const invoiceNumber = inv.invoiceNumber ? String(inv.invoiceNumber).trim() : '';

      if (!invoiceNumber) {
        console.warn('Pominięto fakturę bez invoiceNumber:', inv.ksefNumber);
        continue;
      }

      if (existingInvoiceNumbers.has(invoiceNumber)) {
        continue;
      }

      // Formatowanie Daty i Miesiąca
      const dataFaktury = inv.issueDate || '';
      let miesiacFormat = '';
      if (dataFaktury.length >= 7) {
        const miesiacNum = parseInt(dataFaktury.substring(5, 7), 10);
        if (!isNaN(miesiacNum) && miesiacNum >= 1 && miesiacNum <= 12) {
          miesiacFormat = nazwyMiesiecy[miesiacNum - 1]; // np. "09 (WRZ)"
        }
      }

      // Kwota brutto
      const grossAmount = typeof inv.grossAmount === 'number' ? inv.grossAmount : parseFloat(inv.grossAmount || 0);
      const kwotaBrutto = Number.isFinite(grossAmount) ? grossAmount.toFixed(2).replace('.', ',') : '0,00';

      // Nazwa wystawcy (Sprzedawcy)
      const nazwaWydatku = inv.seller?.name || inv.seller?.nip || 'Brak nazwy';

            // -----------------------------------------------------
      // Wiersz A:M
      //
      // A = puste
      // B = miesiąc
      // C = data
      // D = konto kosztowe
      // E = subkonto
      // F = nazwa wydatku
      // G = kwota brutto
      // H = numer faktury
      // I = sposób płatności
      // J = faktura/paragon
      // K = rozliczone
      // L = przekopiowane do głównego pliku
      // M = komentarz
      // -----------------------------------------------------

      // Mapowanie od kolumny B (pomijamy kolumnę A w tablicy)
      newInvoicesToAppend.push([
        miesiacFormat,
        `'${dataFaktury}`, // Apostrof wymusza traktowanie jako tekst, co naprawi "46266"
        '',
        '',
        nazwaWydatku,
        kwotaBrutto,
        invoiceNumber,
        'przelew',
        'Faktura jest',
        '',
        '',
        ''
      ]);

      existingInvoiceNumbers.add(invoiceNumber);
    }

    // -------------------------------------------------------
    // 9. Zapis do Google Sheets
    // -------------------------------------------------------
    if (newInvoicesToAppend.length > 0) {
      await sheets.spreadsheets.values.append({
        spreadsheetId: sheetId,
        range: "Arkusz1!B:M", // ZMIANA: Zaczynamy wpisywanie sztywno od kolumny B!
        valueInputOption: "USER_ENTERED",
        insertDataOption: "INSERT_ROWS",
        requestBody: {
          values: newInvoicesToAppend,
        },
      });
    }

    // -------------------------------------------------------
    // 10. Odpowiedź
    // -------------------------------------------------------

    return NextResponse.json({
      success: true,
      added: newInvoicesToAppend.length,
      fetched: allInvoices.length,
      message:
        `Pobrano pomyślnie. ` +
        `Znaleziono faktur: ${allInvoices.length}. ` +
        `Dodano nowych: ${newInvoicesToAppend.length}.`,
    });
  } catch (error) {
    console.error("Wystąpił błąd krytyczny:", error);

    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : String(error),
      },
      {
        status: 500,
      },
    );
  }
}
