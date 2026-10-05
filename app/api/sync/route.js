export const runtime = "nodejs";

import { NextResponse } from "next/server";
import { google } from "googleapis";
import crypto from "crypto";

const KSEF_BASE_URL =
  "https://api.ksef.mf.gov.pl/v2";

const SHEET_NAME = "Arkusz1";


// ============================================================
// POMOCNICZE
// ============================================================

async function parseKsefResponse(
  response,
  operationName
) {
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

          return (
            `${item.exceptionCode}: ` +
            `${item.exceptionDescription}${details}`
          );
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
      `${operationName}: ${message} ` +
        `[HTTP ${response.status}]`
    );
  }

  return data;
}


function sleep(ms) {
  return new Promise((resolve) =>
    setTimeout(resolve, ms)
  );
}


// ============================================================
// NORMALIZACJA
// ============================================================

function normalizeText(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/^'/, "")
    .replace(/\s+/g, " ");
}


function normalizeDate(value) {
  const text = normalizeText(value);

  if (!text) {
    return "";
  }

  // YYYY-MM-DD
  const isoMatch =
    text.match(
      /^(\d{4})-(\d{2})-(\d{2})/
    );

  if (isoMatch) {
    return (
      `${isoMatch[1]}-` +
      `${isoMatch[2]}-` +
      `${isoMatch[3]}`
    );
  }

  // DD.MM.YYYY / DD-MM-YYYY / DD/MM/YYYY
  const polishMatch =
    text.match(
      /^(\d{2})[.\-/](\d{2})[.\-/](\d{4})$/
    );

  if (polishMatch) {
    return (
      `${polishMatch[3]}-` +
      `${polishMatch[2]}-` +
      `${polishMatch[1]}`
    );
  }

  return text;
}


function normalizeAmount(value) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return "";
  }

  let text = String(value)
    .trim()
    .toLowerCase()
    .replace(/zł/g, "")
    .replace(/\s/g, "");

  /*
   * Obsługa np.:
   *
   * 18445,08
   * 18 445,08
   * 18445.08
   * 18.445,08
   */

  if (
    text.includes(",") &&
    text.includes(".")
  ) {
    const lastComma =
      text.lastIndexOf(",");

    const lastDot =
      text.lastIndexOf(".");

    if (lastComma > lastDot) {
      // 18.445,08
      text = text
        .replace(/\./g, "")
        .replace(",", ".");
    } else {
      // 18,445.08
      text = text.replace(/,/g, "");
    }
  } else if (text.includes(",")) {
    // 18445,08
    text = text.replace(",", ".");
  }

  const number = Number(text);

  if (!Number.isFinite(number)) {
    return normalizeText(value);
  }

  return number.toFixed(2);
}


// ============================================================
// KLUCZ FALLBACK
// ============================================================

function createInvoiceKey({
  invoiceNumber,
  issueDate,
  sellerName,
  grossAmount,
}) {
  return [
    normalizeText(invoiceNumber),
    normalizeDate(issueDate),
    normalizeText(sellerName),
    normalizeAmount(grossAmount),
  ].join("|");
}


// ============================================================
// KSEF - AUTORYZACJA
// ============================================================

async function authenticateKsef(nipFirmy) {
  const ksefToken =
    process.env.KSEF_TOKEN;

  if (!ksefToken) {
    throw new Error(
      "Brak zmiennej środowiskowej KSEF_TOKEN."
    );
  }


  // ----------------------------------------------------------
  // 1. Challenge
  // ----------------------------------------------------------

  const challengeRes =
    await fetch(
      `${KSEF_BASE_URL}/auth/challenge`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          Accept:
            "application/json",

          "X-Error-Format":
            "problem-details",
        },

        body: JSON.stringify({
          contextIdentifier: {
            type: "Nip",
            value: nipFirmy,
          },
        }),
      }
    );

  const challengeData =
    await parseKsefResponse(
      challengeRes,
      "KSeF Challenge"
    );

  const challenge =
    challengeData.challenge;

  const timestampMs =
    challengeData.timestampMs;

  if (
    !challenge ||
    !timestampMs
  ) {
    throw new Error(
      "KSeF Challenge: brak pola challenge lub timestampMs."
    );
  }


  // ----------------------------------------------------------
  // 2. Publiczny certyfikat
  // ----------------------------------------------------------

  const certRes =
    await fetch(
      `${KSEF_BASE_URL}/security/public-key-certificates`,
      {
        method: "GET",

        headers: {
          Accept:
            "application/json",

          "X-Error-Format":
            "problem-details",
        },
      }
    );

  const certsJson =
    await parseKsefResponse(
      certRes,
      "KSeF Public Key Certificates"
    );

  const cert =
    certsJson.find(
      (item) =>
        Array.isArray(
          item.usage
        ) &&
        item.usage.includes(
          "KsefTokenEncryption"
        )
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

  const base64DerCert =
    cert.certificate;

  const publicKeyId =
    cert.publicKeyId;

  const certificateLines =
    base64DerCert
      .match(/.{1,64}/g)
      ?.join("\n");

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

  const encryptedToken =
    crypto
      .publicEncrypt(
        {
          key: publicKeyPem,

          padding:
            crypto.constants
              .RSA_PKCS1_OAEP_PADDING,

          oaepHash:
            "sha256",
        },

        Buffer.from(
          authMessage,
          "utf8"
        )
      )
      .toString("base64");


  // ----------------------------------------------------------
  // 4. Rozpoczęcie autoryzacji
  // ----------------------------------------------------------

  const authKsefRes =
    await fetch(
      `${KSEF_BASE_URL}/auth/ksef-token`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",

          Accept:
            "application/json",

          "X-Error-Format":
            "problem-details",
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

  const authData =
    await parseKsefResponse(
      authKsefRes,
      "KSeF Auth"
    );

  const referenceNumber =
    authData.referenceNumber;

  const authenticationToken =
    authData
      .authenticationToken
      ?.token;

  if (
    !referenceNumber ||
    !authenticationToken
  ) {
    throw new Error(
      "KSeF Auth: brak danych uwierzytelniania."
    );
  }


  // ----------------------------------------------------------
  // 5. Status autoryzacji
  // ----------------------------------------------------------

  let authStatus = null;

  for (
    let attempt = 1;
    attempt <= 20;
    attempt++
  ) {
    await sleep(500);

    const statusRes =
      await fetch(
        `${KSEF_BASE_URL}/auth/${encodeURIComponent(
          referenceNumber
        )}`,
        {
          method: "GET",

          headers: {
            Accept:
              "application/json",

            Authorization:
              `Bearer ${authenticationToken}`,

            "X-Error-Format":
              "problem-details",
          },
        }
      );

    authStatus =
      await parseKsefResponse(
        statusRes,
        "KSeF Auth Status"
      );

    if (
      authStatus?.status?.code ===
      200
    ) {
      break;
    }

    if (
      authStatus?.status?.code ===
      100
    ) {
      continue;
    }

    throw new Error(
      `KSeF Auth Status: Kod ${
        authStatus?.status?.code ||
        "Nieznany"
      }.`
    );
  }

  if (
    authStatus?.status?.code !==
    200
  ) {
    throw new Error(
      "KSeF Auth Status: Timeout."
    );
  }


  // ----------------------------------------------------------
  // 6. Redeem token
  // ----------------------------------------------------------

  const redeemRes =
    await fetch(
      `${KSEF_BASE_URL}/auth/token/redeem`,
      {
        method: "POST",

        headers: {
          Accept:
            "application/json",

          Authorization:
            `Bearer ${authenticationToken}`,

          "X-Error-Format":
            "problem-details",
        },
      }
    );

  const redeemData =
    await parseKsefResponse(
      redeemRes,
      "KSeF Token Redeem"
    );

  const accessToken =
    redeemData
      ?.accessToken
      ?.token;

  if (!accessToken) {
    throw new Error(
      "KSeF Token Redeem: brak tokena."
    );
  }

  return accessToken;
}


// ============================================================
// GOOGLE SHEETS - INFORMACJE O ARKUSZU
// ============================================================

async function getSheetInfo(
  sheets,
  spreadsheetId
) {
  const response =
    await sheets.spreadsheets.get({
      spreadsheetId,

      fields:
        "sheets.properties",
    });

  const sheetsList =
    response.data.sheets || [];

  const found =
    sheetsList.find(
      (sheet) =>
        sheet.properties?.title ===
        SHEET_NAME
    );

  if (!found) {
    throw new Error(
      `Nie znaleziono arkusza "${SHEET_NAME}".`
    );
  }

  return {
    sheetId:
      found.properties.sheetId,

    title:
      found.properties.title,
  };
}


// ============================================================
// GOOGLE SHEETS - ISTNIEJĄCE FAKTURY
// ============================================================

async function getExistingInvoices(
  sheets,
  spreadsheetId
) {
  const existingKsefNumbers =
    new Set();

  const existingInvoiceKeys =
    new Set();

  /*
   * Czytamy B:O.
   *
   * K, L, M pozostają nietknięte.
   *
   * N = ksefNumber
   */

  const response =
    await sheets.spreadsheets.values.get(
      {
        spreadsheetId,

        range:
          `${SHEET_NAME}!B:O`,

        valueRenderOption:
          "FORMATTED_VALUE",
      }
    );

  const rows =
    response.data.values || [];

  for (const row of rows) {
    /*
     * B = 0
     * C = 1
     * D = 2
     * E = 3
     * F = 4
     * G = 5
     * H = 6
     * I = 7
     * J = 8
     * K = 9
     * L = 10
     * M = 11
     * N = 12
     * O = 13
     */

    const issueDate =
      String(row[1] || "")
        .trim()
        .replace(/^'/, "");

    const sellerName =
      String(
        row[4] || ""
      ).trim();

    const grossAmount =
      row[5];

    const invoiceNumber =
      String(
        row[6] || ""
      ).trim();

    const ksefNumber =
      String(
        row[12] || ""
      ).trim();


    // --------------------------------------------------------
    // Główny identyfikator - KSeF
    // --------------------------------------------------------

    if (ksefNumber) {
      existingKsefNumbers.add(
        ksefNumber
      );
    }


    // --------------------------------------------------------
    // Fallback dla starych rekordów
    // --------------------------------------------------------

    if (
      invoiceNumber &&
      issueDate
    ) {
      const invoiceKey =
        createInvoiceKey({
          invoiceNumber,
          issueDate,
          sellerName,
          grossAmount,
        });

      existingInvoiceKeys.add(
        invoiceKey
      );
    }
  }

  return {
    existingKsefNumbers,
    existingInvoiceKeys,
  };
}


// ============================================================
// KSEF - POBIERANIE FAKTUR
// ============================================================

async function fetchInvoicesFromKsef(
  accessToken
) {
  const now =
    new Date();

  const threeMonthsAgo =
    new Date(now);

  threeMonthsAgo.setMonth(
    threeMonthsAgo.getMonth() - 3
  );

  let fromISO =
    threeMonthsAgo.toISOString();

  const toISO =
    now.toISOString();

  const allInvoices = [];

  let pageOffset = 0;
  let hasMore = true;
  let isTruncated = false;

  let safetyCounter = 0;

  while (hasMore) {
    safetyCounter++;

    if (
      safetyCounter > 1000
    ) {
      throw new Error(
        "KSeF: przekroczono limit stron synchronizacji."
      );
    }

    const url =
      `${KSEF_BASE_URL}/invoices/query/metadata` +
      `?pageSize=250` +
      `&pageOffset=${pageOffset}` +
      `&sortOrder=Asc`;

    const syncRes =
      await fetch(
        url,
        {
          method: "POST",

          headers: {
            Accept:
              "application/json",

            "Content-Type":
              "application/json",

            Authorization:
              `Bearer ${accessToken}`,

            "X-Error-Format":
              "problem-details",
          },

          body: JSON.stringify({
            subjectType:
              "Subject2",

            dateRange: {
              dateType:
                "PermanentStorage",

              from:
                fromISO,

              to:
                toISO,

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
    // Następna strona
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
        lastInvoice
          ?.permanentStorageDate;

      if (!lastDate) {
        throw new Error(
          "KSeF: wynik jest ucięty, ale ostatnia faktura nie ma permanentStorageDate."
        );
      }

      /*
       * Jeżeli KSeF zwróci dokładnie
       * ten sam punkt rozpoczęcia,
       * przerywamy zamiast zapętlać requesty.
       */

      if (
        lastDate ===
        fromISO
      ) {
        break;
      }

      fromISO =
        lastDate;

      pageOffset = 0;

      continue;
    }

    break;
  }

  return allInvoices;
}


// ============================================================
// PRZYGOTOWANIE NOWYCH FAKTUR
// ============================================================

function prepareNewInvoices(
  allInvoices,
  existingKsefNumbers,
  existingInvoiceKeys
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

  const seenKsefNumbers =
    new Set();

  const seenInvoiceKeys =
    new Set();

  const rows = [];

  const ksefNumbers = [];

  for (
    const inv of allInvoices
  ) {
    // --------------------------------------------------------
    // Dane KSeF
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


    if (
      !ksefNumber ||
      !invoiceNumber ||
      !issueDate
    ) {
      continue;
    }


    // --------------------------------------------------------
    // 1. Duplikat w bieżącym pobraniu
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
    // 2. Duplikat już zapisany w N
    // --------------------------------------------------------

    if (
      existingKsefNumbers.has(
        ksefNumber
      )
    ) {
      continue;
    }


    // --------------------------------------------------------
    // Kwota
    // --------------------------------------------------------

    const grossAmount =
      typeof inv.grossAmount ===
      "number"
        ? inv.grossAmount
        : parseFloat(
            String(
              inv.grossAmount ??
              "0"
            )
              .replace(/\s/g, "")
              .replace(",", ".")
          );


    // --------------------------------------------------------
    // 3. Fallback dla starych rekordów
    // --------------------------------------------------------

    const invoiceKey =
      createInvoiceKey({
        invoiceNumber,
        issueDate,
        sellerName,
        grossAmount,
      });

    if (
      existingInvoiceKeys.has(
        invoiceKey
      )
    ) {
      continue;
    }


    // --------------------------------------------------------
    // 4. Duplikat w bieżącym pobraniu
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


    // --------------------------------------------------------
    // Dodajemy również do istniejących
    // --------------------------------------------------------

    existingKsefNumbers.add(
      ksefNumber
    );

    existingInvoiceKeys.add(
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
    // B:J
    // --------------------------------------------------------
    //
    // B = miesiąc
    // C = data
    // D = puste
    // E = puste
    // F = kontrahent
    // G = kwota
    // H = numer faktury
    // I = uzupelnic
    // J = uzupelnic
    //
    // K, L, M NIE SĄ DOTYKANE.
    //
    // N zostanie zapisane osobno.
    // --------------------------------------------------------

    rows.push([
      miesiacFormat,
      `'${issueDate}`,
      "",
      "",
      sellerName,
      kwotaBrutto,
      invoiceNumber,
      "uzupelnic",
      "uzupelnic",
    ]);

    ksefNumbers.push(
      ksefNumber
    );
  }

  return {
    rows,
    ksefNumbers,
  };
}


// ============================================================
// UKRYWANIE KOLUMNY N
// ============================================================

async function hideTechnicalColumnN(
  sheets,
  spreadsheetId,
  sheetId
) {
  /*
   * Kolumny są indeksowane od 0:
   *
   * A = 0
   * B = 1
   * ...
   * N = 13
   *
   * endIndex jest wyłączny,
   * więc N to 13 -> 14.
   */

  await sheets.spreadsheets.batchUpdate(
    {
      spreadsheetId,

      requestBody: {
        requests: [
          {
            updateDimensionProperties: {
              range: {
                sheetId,

                dimension:
                  "COLUMNS",

                startIndex: 13,

                endIndex: 14,
              },

              properties: {
                hiddenByUser:
                  true,
              },

              fields:
                "hiddenByUser",
            },
          },
        ],
      },
    }
  );
}


// ============================================================
// ZAPIS N - KSEF NUMBER
// ============================================================

async function writeKsefNumbers(
  sheets,
  spreadsheetId,
  startRow,
  endRow,
  ksefNumbers
) {
  if (
    !ksefNumbers.length
  ) {
    return;
  }

  const expectedRows =
    endRow - startRow + 1;

  if (
    expectedRows !==
    ksefNumbers.length
  ) {
    throw new Error(
      "Google Sheets: liczba dodanych wierszy nie zgadza się z liczbą ksefNumber."
    );
  }

  await sheets.spreadsheets.values.update(
    {
      spreadsheetId,

      range:
        `${SHEET_NAME}!N${startRow}:N${endRow}`,

      valueInputOption:
        "RAW",

      requestBody: {
        values:
          ksefNumbers.map(
            (number) => [
              number,
            ]
          ),
      },
    }
  );
}


// ============================================================
// ODCZYT NUMERÓW WIERSZY Z UPDATED RANGE
// ============================================================

function parseUpdatedRows(
  updatedRange
) {
  /*
   * Obsługujemy:
   *
   * Arkusz1!B131:J135
   *
   * oraz:
   *
   * Arkusz1!B131:J131
   */

  const rowMatch =
    updatedRange.match(
      /![A-Z]+(\d+)(?::[A-Z]+(\d+))?/
    );

  if (!rowMatch) {
    throw new Error(
      `Nie udało się odczytać numerów wierszy z zakresu: ${updatedRange}`
    );
  }

  const startRow =
    parseInt(
      rowMatch[1],
      10
    );

  const endRow =
    rowMatch[2]
      ? parseInt(
          rowMatch[2],
          10
        )
      : startRow;

  return {
    startRow,
    endRow,
  };
}


// ============================================================
// POST /api/sync
// ============================================================

export async function POST(
  request
)
{
  console.log("🔥 DEDUPE-V3 AKTYWNY");
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
      ).replace(
        /\D/g,
        ""
      );

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
    // 7. Informacje o arkuszu
    // --------------------------------------------------------

    const sheetInfo =
      await getSheetInfo(
        sheets,
        sheetId
      );


    // --------------------------------------------------------
    // 8. Odczyt istniejących faktur
    // --------------------------------------------------------

    let existing =
      await getExistingInvoices(
        sheets,
        sheetId
      );


    // --------------------------------------------------------
    // 9. Autoryzacja KSeF
    // --------------------------------------------------------

    const accessToken =
      await authenticateKsef(
        nipFirmy
      );


    // --------------------------------------------------------
    // 10. Pobranie faktur
    // --------------------------------------------------------

    const allInvoices =
      await fetchInvoicesFromKsef(
        accessToken
      );


    // --------------------------------------------------------
    // 11. Ponowny odczyt arkusza
    // --------------------------------------------------------
    //
    // Robimy to tuż przed deduplikacją,
    // aby mieć możliwie najnowszy stan.
    // --------------------------------------------------------

    existing =
      await getExistingInvoices(
        sheets,
        sheetId
      );


    // --------------------------------------------------------
    // 12. DEDUPLIKACJA
    // --------------------------------------------------------

    const prepared =
      prepareNewInvoices(
        allInvoices,
        existing.existingKsefNumbers,
        existing.existingInvoiceKeys
      );


    // --------------------------------------------------------
    // 13. Nic nowego
    // --------------------------------------------------------

    if (
      prepared.rows.length === 0
    ) {
      /*
       * Nawet jeśli kolumna N była kiedyś
       * odkryta, ustawiamy ją ponownie jako ukrytą.
       */

      await hideTechnicalColumnN(
        sheets,
        sheetId,
        sheetInfo.sheetId
      );

      return NextResponse.json({
        success: true,

        fetched:
          allInvoices.length,

        added: 0,

        message:
          `Znaleziono ${allInvoices.length} faktur ` +
          `w KSeF. Wszystkie są już w arkuszu.`,
      });
    }


    // --------------------------------------------------------
    // 14. Zapis B:J
    // --------------------------------------------------------
    //
    // UWAGA:
    // Nie zapisujemy B:O.
    //
    // Dzięki temu K, L oraz M pozostają
    // całkowicie nietknięte.
    // --------------------------------------------------------

    const appendResponse =
      await sheets.spreadsheets.values.append(
        {
          spreadsheetId:
            sheetId,

          range:
            `${SHEET_NAME}!B:J`,

          valueInputOption:
            "USER_ENTERED",

          insertDataOption:
            "INSERT_ROWS",

          requestBody: {
            values:
              prepared.rows,
          },
        }
      );


    // --------------------------------------------------------
    // 15. Ustalenie numerów wierszy
    // --------------------------------------------------------

    const updatedRange =
      appendResponse
        ?.data
        ?.updates
        ?.updatedRange;

    if (!updatedRange) {
      throw new Error(
        "Google Sheets: nie udało się ustalić zakresu dodanych faktur."
      );
    }

    const {
      startRow,
      endRow,
    } =
      parseUpdatedRows(
        updatedRange
      );


    // --------------------------------------------------------
    // 16. Zapis KSeF Number do N
    // --------------------------------------------------------

    await writeKsefNumbers(
      sheets,
      sheetId,
      startRow,
      endRow,
      prepared.ksefNumbers
    );


    // --------------------------------------------------------
    // 17. Ukrycie N
    // --------------------------------------------------------

    await hideTechnicalColumnN(
      sheets,
      sheetId,
      sheetInfo.sheetId
    );


    // --------------------------------------------------------
    // 18. Odpowiedź
    // --------------------------------------------------------

    return NextResponse.json({
  success: true,

  version: "DEDUPE-V3-2026-10-05",

  fetched:
    allInvoices.length,

  added:
    prepared.rows.length,

  message:
    `Znaleziono ${allInvoices.length} faktur ` +
    `w KSeF. Dodano nowych: ` +
    `${prepared.rows.length}.`,
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
