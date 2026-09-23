import { NextResponse } from "next/server";
import { google } from "googleapis";
import crypto from "crypto";

const KSEF_BASE_URL = "https://api.ksef.mf.gov.pl/v2";

// ============================================================
// POMOCNICZE
// ============================================================

async function parseKsefResponse(response, operationName) {
  const text = await response.text();

  let data;

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(
      `${operationName}: KSeF zwrócił niepoprawny JSON/HTML. ` +
        `HTTP ${response.status}: ${text.substring(0, 500)}`
    );
  }

  if (!response.ok) {
    const exceptionDetails =
      data?.exception?.exceptionDetailList
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

    throw new Error(
      `${operationName}: ${message} [HTTP ${response.status}]`
    );
  }

  return data;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================
// NORMALIZACJA
// ============================================================

function normalizeText(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/^'/, "");
}

function normalizeAmount(value) {
  if (value === null || value === undefined || value === "") {
    return "";
  }

  const normalized = String(value)
    .trim()
    .replace(",", ".");

  const number = Number(normalized);

  if (!Number.isFinite(number)) {
    return normalized;
  }

  return number.toFixed(2);
}

/**
 * Klucz pomocniczy do rozpoznawania faktury.
 *
 * NIE jest zapisywany do Google Sheets.
 */
function createInvoiceKey({
  invoiceNumber,
  issueDate,
  sellerName,
  grossAmount,
}) {
  return [
    normalizeText(invoiceNumber),
    normalizeText(issueDate),
    normalizeText(sellerName),
    normalizeAmount(grossAmount),
  ].join("|");
}

// ============================================================
// KSEF - AUTORYZACJA
// ============================================================

async function authenticateKsef(nipFirmy) {
  const ksefToken = process.env.KSEF_TOKEN;

  if (!ksefToken) {
    throw new Error(
      "Brak zmiennej środowiskowej KSEF_TOKEN."
    );
  }

  // ----------------------------------------------------------
  // 1. Challenge
  // ----------------------------------------------------------

  const challengeRes = await fetch(
    `${KSEF_BASE_URL}/auth/challenge`,
    {
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
    }
  );

  const challengeData = await parseKsefResponse(
    challengeRes,
    "KSeF Challenge"
  );

  const challenge = challengeData.challenge;
  const timestampMs = challengeData.timestampMs;

  if (!challenge || !timestampMs) {
    throw new Error(
      "KSeF Challenge: brak pola challenge lub timestampMs."
    );
  }

  // ----------------------------------------------------------
  // 2. Publiczny certyfikat KSeF
  // ----------------------------------------------------------

  const certRes = await fetch(
    `${KSEF_BASE_URL}/security/public-key-certificates`,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        "X-Error-Format": "problem-details",
      },
    }
  );

  const certsJson = await parseKsefResponse(
    certRes,
    "KSeF Public Key Certificates"
  );

  const cert = certsJson.find(
    (item) =>
      Array.isArray(item.usage) &&
      item.usage.includes("KsefTokenEncryption")
  );

  if (
    !cert ||
    !cert.certificate ||
    !cert.publicKeyId
  ) {
    throw new Error(
      "KSeF: nie znaleziono odpowiedniego certyfikatu (KsefTokenEncryption)."
    );
  }

  const base64DerCert = cert.certificate;
  const publicKeyId = cert.publicKeyId;

  const certificateLines =
    base64DerCert.match(/.{1,64}/g)?.join("\n");

  if (!certificateLines) {
    throw new Error(
      "KSeF: certyfikat ma nieprawidłowy format."
    );
  }

  const publicKeyPem =
    `-----BEGIN CERTIFICATE-----\n` +
    `${certificateLines}\n` +
    `-----END CERTIFICATE-----`;

  // ----------------------------------------------------------
  // 3. Szyfrowanie tokena
  // ----------------------------------------------------------

  const authMessage =
    `${ksefToken}|${timestampMs}`;

  const encryptedToken = crypto
    .publicEncrypt(
      {
        key: publicKeyPem,
        padding:
          crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(authMessage, "utf8")
    )
    .toString("base64");

  // ----------------------------------------------------------
  // 4. Rozpoczęcie autoryzacji
  // ----------------------------------------------------------

  const authKsefRes = await fetch(
    `${KSEF_BASE_URL}/auth/ksef-token`,
    {
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
    }
  );

  const authData = await parseKsefResponse(
    authKsefRes,
    "KSeF Auth"
  );

  const referenceNumber =
    authData.referenceNumber;

  const authenticationToken =
    authData.authenticationToken?.token;

  if (
    !referenceNumber ||
    !authenticationToken
  ) {
    throw new Error(
      "KSeF Auth: brak danych uwierzytelniania."
    );
  }

  // ----------------------------------------------------------
  // 5. Oczekiwanie na zakończenie autoryzacji
  // ----------------------------------------------------------

  let authStatus = null;

  for (
    let attempt = 1;
    attempt <= 20;
    attempt++
  ) {
    await sleep(500);

    const statusRes = await fetch(
      `${KSEF_BASE_URL}/auth/${encodeURIComponent(
        referenceNumber
      )}`,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization:
            `Bearer ${authenticationToken}`,
          "X-Error-Format":
            "problem-details",
        },
      }
    );

    authStatus = await parseKsefResponse(
      statusRes,
      "KSeF Auth Status"
    );

    if (authStatus?.status?.code === 200) {
      break;
    }

    if (authStatus?.status?.code === 100) {
      continue;
    }

    throw new Error(
      `KSeF Auth Status: Kod ${
        authStatus?.status?.code ||
        "Nieznany"
      }.`
    );
  }

  if (authStatus?.status?.code !== 200) {
    throw new Error(
      "KSeF Auth Status: Timeout."
    );
  }

  // ----------------------------------------------------------
  // 6. Redeem access token
  // ----------------------------------------------------------

  const redeemRes = await fetch(
    `${KSEF_BASE_URL}/auth/token/redeem`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization:
          `Bearer ${authenticationToken}`,
        "X-Error-Format":
          "problem-details",
      },
    }
  );

  const redeemData = await parseKsefResponse(
    redeemRes,
    "KSeF Token Redeem"
  );

  const accessToken =
    redeemData?.accessToken?.token;

  if (!accessToken) {
    throw new Error(
      "KSeF Token Redeem: brak tokena."
    );
  }

  return accessToken;
}

// ============================================================
// GOOGLE SHEETS
// ============================================================

/**
 * Pobiera istniejące faktury z arkusza.
 *
 * Czytamy WYŁĄCZNIE:
 *
 * B = miesiąc
 * C = data
 * D = puste
 * E = puste
 * F = sprzedawca
 * G = kwota
 * H = numer faktury
 *
 * ŻADNE metadane KSeF nie są pobierane z arkusza.
 */
async function getExistingInvoices(
  sheets,
  sheetId
) {
  const existingKeys = new Set();

  const response =
    await sheets.spreadsheets.values.get({
      spreadsheetId: sheetId,
      range: "Arkusz1!B:H",
      valueRenderOption:
        "FORMATTED_VALUE",
    });

  const rows =
    response.data.values || [];

  for (const row of rows) {
    /*
     * B = row[0]
     * C = row[1]
     * D = row[2]
     * E = row[3]
     * F = row[4]
     * G = row[5]
     * H = row[6]
     */

    const issueDate =
      String(row[1] || "")
        .trim()
        .replace(/^'/, "");

    const sellerName =
      String(row[4] || "").trim();

    const grossAmount =
      row[5];

    const invoiceNumber =
      String(row[6] || "").trim();

    if (
      !invoiceNumber ||
      !issueDate
    ) {
      continue;
    }

    const invoiceKey =
      createInvoiceKey({
        invoiceNumber,
        issueDate,
        sellerName,
        grossAmount,
      });

    existingKeys.add(invoiceKey);
  }

  return existingKeys;
}

// ============================================================
// KSEF - POBIERANIE FAKTUR
// ============================================================

async function fetchInvoicesFromKsef(
  accessToken
) {
  const teraz = new Date();

  /*
   * KSeF pozwala obecnie na zapytania
   * o metadane maksymalnie w zakresie 3 miesięcy.
   */

  const trzyMiesiaceTemu =
    new Date(teraz);

  trzyMiesiaceTemu.setMonth(
    trzyMiesiaceTemu.getMonth() - 3
  );

  let fromISO =
    trzyMiesiaceTemu.toISOString();

  const toISO =
    teraz.toISOString();

  const allInvoices = [];

  let pageOffset = 0;
  let hasMore = true;
  let isTruncated = false;

  let safetyCounter = 0;

  while (hasMore) {
    safetyCounter++;

    if (safetyCounter > 1000) {
      throw new Error(
        "KSeF: przekroczono limit stron synchronizacji."
      );
    }

    const url =
      `${KSEF_BASE_URL}/invoices/query/metadata` +
      `?pageSize=250` +
      `&pageOffset=${pageOffset}` +
      `&sortOrder=Asc`;

    const syncRes = await fetch(
      url,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type":
            "application/json",
          Authorization:
            `Bearer ${accessToken}`,
          "X-Error-Format":
            "problem-details",
        },
        body: JSON.stringify({
          subjectType: "Subject2",
          dateRange: {
            dateType:
              "PermanentStorage",
            from: fromISO,
            to: toISO,
            restrictToPermanentStorageHwmDate:
              true,
          },
        }),
      }
    );

    const syncData =
      await parseKsefResponse(
        syncRes,
        "KSeF Invoice Metadata"
      );

    const invoices =
      Array.isArray(
        syncData.invoices
      )
        ? syncData.invoices
        : [];

    allInvoices.push(
      ...invoices
    );

    hasMore =
      syncData.hasMore === true;

    isTruncated =
      syncData.isTruncated === true;

    // --------------------------------------------------------
    // Kolejna strona
    // --------------------------------------------------------

    if (
      hasMore &&
      !isTruncated
    ) {
      pageOffset += 250;
      continue;
    }

    // --------------------------------------------------------
    // Wynik ucięty
    // --------------------------------------------------------

    if (
      hasMore &&
      isTruncated
    ) {
      const lastInvoice =
        invoices[
          invoices.length - 1
        ];

      const lastDate =
        lastInvoice?.permanentStorageDate;

      if (!lastDate) {
        throw new Error(
          "KSeF: wynik jest ucięty, ale ostatnia faktura nie ma permanentStorageDate."
        );
      }

      fromISO = lastDate;
      pageOffset = 0;

      continue;
    }

    break;
  }

  return allInvoices;
}

// ============================================================
// DEDUPLIKACJA
// ============================================================

function prepareNewInvoices(
  allInvoices,
  existingKeys
) {
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

  /*
   * Chroni przed powtórzeniem
   * tego samego ksefNumber
   * w jednym pobraniu.
   */
  const seenKsefNumbers =
    new Set();

  /*
   * Chroni przed powtórzeniem
   * tych samych danych biznesowych
   * w jednym pobraniu.
   */
  const seenInvoiceKeys =
    new Set();

  const newInvoices = [];

  for (const inv of allInvoices) {
    // --------------------------------------------------------
    // Dane z KSeF
    // --------------------------------------------------------

    const ksefNumber =
      inv.ksefNumber
        ? String(
            inv.ksefNumber
          ).trim()
        : "";

    const invoiceNumber =
      inv.invoiceNumber
        ? String(
            inv.invoiceNumber
          ).trim()
        : "";

    const issueDate =
      inv.issueDate
        ? String(
            inv.issueDate
          ).trim()
        : "";

    const sellerName =
      inv.seller?.name ||
      inv.seller?.nip ||
      "Brak nazwy";

    /*
     * Faktura bez tych danych
     * nie może zostać poprawnie
     * zidentyfikowana.
     */
    if (
      !ksefNumber ||
      !invoiceNumber ||
      !issueDate
    ) {
      continue;
    }

    // --------------------------------------------------------
    // POZIOM 1
    // Ten sam numer KSeF
    // --------------------------------------------------------

    if (
      seenKsefNumbers.has(
        ksefNumber
      )
    ) {
      continue;
    }

    seenKsefNumbers.add(
      ksefNumber
    );

    // --------------------------------------------------------
    // Kwota brutto
    // --------------------------------------------------------

    const grossAmount =
      typeof inv.grossAmount ===
      "number"
        ? inv.grossAmount
        : parseFloat(
            String(
              inv.grossAmount ??
                "0"
            ).replace(",", ".")
          );

    // --------------------------------------------------------
    // POZIOM 2
    // Czy faktura już jest w arkuszu?
    // --------------------------------------------------------

    const invoiceKey =
      createInvoiceKey({
        invoiceNumber,
        issueDate,
        sellerName,
        grossAmount,
      });

    if (
      existingKeys.has(
        invoiceKey
      )
    ) {
      continue;
    }

    // --------------------------------------------------------
    // POZIOM 3
    // Czy ta sama faktura została
    // już przygotowana w tym pobraniu?
    // --------------------------------------------------------

    if (
      seenInvoiceKeys.has(
        invoiceKey
      )
    ) {
      continue;
    }

    seenInvoiceKeys.add(
      invoiceKey
    );

    /*
     * Dodajemy klucz od razu do existingKeys.
     *
     * Dzięki temu kolejna faktura
     * w tym samym przebiegu nie przejdzie
     * ponownie.
     */
    existingKeys.add(
      invoiceKey
    );

    // --------------------------------------------------------
    // Miesiąc
    // --------------------------------------------------------

    let miesiacFormat = "";

    if (
      issueDate.length >= 7
    ) {
      const miesiacNum =
        parseInt(
          issueDate.substring(
            5,
            7
          ),
          10
        );

      if (
        !isNaN(miesiacNum) &&
        miesiacNum >= 1 &&
        miesiacNum <= 12
      ) {
        miesiacFormat =
          nazwyMiesiecy[
            miesiacNum - 1
          ];
      }
    }

    // --------------------------------------------------------
    // Kwota
    // --------------------------------------------------------

    const kwotaBrutto =
      Number.isFinite(
        grossAmount
      )
        ? grossAmount
            .toFixed(2)
            .replace(".", ",")
        : "0,00";

    // --------------------------------------------------------
    // TYLKO B:H
    // --------------------------------------------------------

    newInvoices.push([
      miesiacFormat, // B
      `'${issueDate}`, // C
      "", // D
      "", // E
      sellerName, // F
      kwotaBrutto, // G
      invoiceNumber, // H
    ]);
  }

  return newInvoices;
}

// ============================================================
// POST /api/sync
// ============================================================

export async function POST(request) {
  try {
    // --------------------------------------------------------
    // 1. Request
    // --------------------------------------------------------

    const body =
      await request.json();

    const {
      secretKey,
      sheetId,
    } = body;

    // --------------------------------------------------------
    // 2. API Secret
    // --------------------------------------------------------

    if (
      secretKey !==
      process.env.API_SECRET_KEY
    ) {
      return NextResponse.json(
        {
          error:
            "Odmowa dostępu. Nieprawidłowy klucz.",
        },
        {
          status: 401,
        }
      );
    }

    // --------------------------------------------------------
    // 3. Sheet ID
    // --------------------------------------------------------

    if (!sheetId) {
      return NextResponse.json(
        {
          error:
            "Brak sheetId.",
        },
        {
          status: 400,
        }
      );
    }

    // --------------------------------------------------------
    // 4. NIP
    // --------------------------------------------------------

    const nipFirmy =
      (
        process.env.NIP_FIRMY ||
        ""
      ).replace(/\D/g, "");

    if (
      nipFirmy.length !== 10
    ) {
      throw new Error(
        "NIP_FIRMY musi mieć 10 cyfr."
      );
    }

    // --------------------------------------------------------
    // 5. Google credentials
    // --------------------------------------------------------

    const googlePrivateKey =
      (
        process.env
          .GOOGLE_PRIVATE_KEY ||
        ""
      ).replace(
        /\\n/g,
        "\n"
      );

    const googleServiceAccountEmail =
      process.env
        .GOOGLE_SERVICE_ACCOUNT_EMAIL;

    if (
      !googleServiceAccountEmail ||
      !googlePrivateKey
    ) {
      throw new Error(
        "Brak konfiguracji Google (Email lub Klucz)."
      );
    }

    // --------------------------------------------------------
    // 6. Google Auth
    // --------------------------------------------------------

    const auth =
      new google.auth.GoogleAuth({
        credentials: {
          client_email:
            googleServiceAccountEmail,
          private_key:
            googlePrivateKey,
        },
        scopes: [
          "https://www.googleapis.com/auth/spreadsheets",
        ],
      });

    const sheets =
      google.sheets({
        version: "v4",
        auth,
      });

    // --------------------------------------------------------
    // 7. PIERWSZE sprawdzenie arkusza
    // --------------------------------------------------------

    let existingKeys =
      await getExistingInvoices(
        sheets,
        sheetId
      );

    // --------------------------------------------------------
    // 8. KSeF authentication
    // --------------------------------------------------------

    const accessToken =
      await authenticateKsef(
        nipFirmy
      );

    // --------------------------------------------------------
    // 9. Pobierz faktury
    // --------------------------------------------------------

    const allInvoices =
      await fetchInvoicesFromKsef(
        accessToken
      );

    // --------------------------------------------------------
    // 10. WAŻNE:
    // Ponownie odczytujemy arkusz.
    //
    // Dzięki temu nawet jeśli dane zmieniły się
    // podczas pobierania z KSeF, sprawdzamy
    // możliwie najnowszy stan przed zapisem.
    // --------------------------------------------------------

    existingKeys =
      await getExistingInvoices(
        sheets,
        sheetId
      );

    // --------------------------------------------------------
    // 11. DEDUPLIKACJA
    // --------------------------------------------------------

    const newInvoices =
      prepareNewInvoices(
        allInvoices,
        existingKeys
      );

    // --------------------------------------------------------
    // 12. ZAPIS WYŁĄCZNIE B:H
    // --------------------------------------------------------

    if (
      newInvoices.length > 0
    ) {
      await sheets.spreadsheets.values.append(
        {
          spreadsheetId:
            sheetId,

          range:
            "Arkusz1!B:H",

          valueInputOption:
            "USER_ENTERED",

          insertDataOption:
            "INSERT_ROWS",

          requestBody: {
            values:
              newInvoices,
          },
        }
      );
    }

    // --------------------------------------------------------
    // 13. Odpowiedź
    // --------------------------------------------------------

    return NextResponse.json({
      success: true,
      fetched:
        allInvoices.length,
      added:
        newInvoices.length,
      message:
        `Znaleziono faktur w KSeF: ${allInvoices.length}. ` +
        `Dodano nowych: ${newInvoices.length}.`,
    });
  } catch (error) {
    console.error(
      "Wystąpił błąd krytyczny:",
      error
    );

    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : String(error),
      },
      {
        status: 500,
      }
    );
  }
}