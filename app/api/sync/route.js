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
    throw new Error(
      `${operationName}: KSeF zwrócił niepoprawny JSON/HTML. HTTP ${response.status}: ${text.substring(
        0,
        500
      )}`
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

    throw new Error(
      `${operationName}: ${message} [HTTP ${response.status}]`
    );
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
// Normalizacja tekstu
// =========================================================
function normalizeText(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/^'/, "");
}

// =========================================================
// Normalizacja kwoty
// =========================================================
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

// =========================================================
// Klucz pomocniczy dla starych danych
//
// Głównym identyfikatorem jest ksefNumber.
// Ten klucz służy jako zabezpieczenie dla istniejących
// rekordów, które nie mają jeszcze ksefNumber.
// =========================================================
function createLegacyKey({
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

// =========================================================
// Ukrywanie kolumn, których pracownik nie powinien widzieć
//
// Widoczne:
// B = miesiąc
// C = data
// F = nazwa wydatku
// G = kwota
// H = numer faktury
//
// Ukryte:
// A
// D:E
// I:M
//
// W K i L nadal przechowujemy dane techniczne KSeF.
// =========================================================
async function hideNonEssentialColumns(sheets, sheetId) {
  const spreadsheet = await sheets.spreadsheets.get({
    spreadsheetId: sheetId,
    fields: "sheets.properties",
  });

  const sheet = spreadsheet.data.sheets?.find(
    (item) => item.properties?.title === "Arkusz1"
  );

  if (!sheet?.properties?.sheetId) {
    throw new Error(
      "Nie znaleziono arkusza 'Arkusz1'."
    );
  }

  const numericSheetId = sheet.properties.sheetId;

  await sheets.spreadsheets.batchUpdate({
    spreadsheetId: sheetId,
    requestBody: {
      requests: [
        // A
        {
          updateDimensionProperties: {
            range: {
              sheetId: numericSheetId,
              dimension: "COLUMNS",
              startIndex: 0,
              endIndex: 1,
            },
            properties: {
              hiddenByUser: true,
            },
            fields: "hiddenByUser",
          },
        },

        // D:E
        {
          updateDimensionProperties: {
            range: {
              sheetId: numericSheetId,
              dimension: "COLUMNS",
              startIndex: 3,
              endIndex: 5,
            },
            properties: {
              hiddenByUser: true,
            },
            fields: "hiddenByUser",
          },
        },

        // I:M
        {
          updateDimensionProperties: {
            range: {
              sheetId: numericSheetId,
              dimension: "COLUMNS",
              startIndex: 8,
              endIndex: 13,
            },
            properties: {
              hiddenByUser: true,
            },
            fields: "hiddenByUser",
          },
        },
      ],
    },
  });
}

// =========================================================
// KSeF - uwierzytelnienie tokenem KSeF
// =========================================================
async function authenticateKsef(nipFirmy) {
  const ksefToken = process.env.KSEF_TOKEN;

  if (!ksefToken) {
    throw new Error(
      "Brak zmiennej środowiskowej KSEF_TOKEN."
    );
  }

  // -------------------------------------------------------
  // 1. Challenge
  // -------------------------------------------------------
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

  if (!cert || !cert.certificate || !cert.publicKeyId) {
    throw new Error(
      "KSeF: nie znaleziono odpowiedniego certyfikatu (KsefTokenEncryption)."
    );
  }

  const base64DerCert = cert.certificate;
  const publicKeyId = cert.publicKeyId;

  const certificateLines = base64DerCert
    .match(/.{1,64}/g)
    ?.join("\n");

  const publicKeyPem = `-----BEGIN CERTIFICATE-----
${certificateLines}
-----END CERTIFICATE-----`;

  // -------------------------------------------------------
  // 3. Zbudowanie wiadomości i RSA-OAEP
  // -------------------------------------------------------
  const authMessage = `${ksefToken}|${timestampMs}`;

  const encryptedToken = crypto
    .publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(authMessage, "utf8")
    )
    .toString("base64");

  // -------------------------------------------------------
  // 4. Rozpoczęcie uwierzytelniania tokenem
  // -------------------------------------------------------
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

  const referenceNumber = authData.referenceNumber;
  const authenticationToken =
    authData.authenticationToken?.token;

  if (!referenceNumber || !authenticationToken) {
    throw new Error(
      "KSeF Auth: brak danych uwierzytelniania."
    );
  }

  // -------------------------------------------------------
  // 5. Czekamy na zakończenie uwierzytelniania
  // -------------------------------------------------------
  let authStatus = null;

  for (let attempt = 1; attempt <= 20; attempt++) {
    await sleep(500);

    const statusRes = await fetch(
      `${KSEF_BASE_URL}/auth/${encodeURIComponent(
        referenceNumber
      )}`,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${authenticationToken}`,
          "X-Error-Format": "problem-details",
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
        authStatus?.status?.code || "Nieznany"
      }.`
    );
  }

  if (authStatus?.status?.code !== 200) {
    throw new Error(
      "KSeF Auth Status: Timeout."
    );
  }

  // -------------------------------------------------------
  // 6. Pobranie właściwego accessToken
  // -------------------------------------------------------
  const redeemRes = await fetch(
    `${KSEF_BASE_URL}/auth/token/redeem`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${authenticationToken}`,
        "X-Error-Format": "problem-details",
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

// =========================================================
// POST /api/sync
// =========================================================
export async function POST(request) {
  try {
    // =====================================================
    // 1. Dane wejściowe
    // =====================================================
    const body = await request.json();

    const { secretKey, sheetId } = body;

    // =====================================================
    // 2. Autoryzacja naszego API
    // =====================================================
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

    if (!sheetId) {
      return NextResponse.json(
        {
          error: "Brak sheetId.",
        },
        {
          status: 400,
        }
      );
    }

    // =====================================================
    // 3. NIP firmy
    // =====================================================
    const nipFirmy = (
      process.env.NIP_FIRMY || ""
    ).replace(/\D/g, "");

    if (nipFirmy.length !== 10) {
      throw new Error(
        "NIP_FIRMY musi mieć 10 cyfr."
      );
    }

    // =====================================================
    // 4. Konfiguracja Google Sheets
    // =====================================================
    const googlePrivateKey = (
      process.env.GOOGLE_PRIVATE_KEY || ""
    ).replace(/\\n/g, "\n");

    const googleServiceAccountEmail =
      process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;

    if (
      !googleServiceAccountEmail ||
      !googlePrivateKey
    ) {
      throw new Error(
        "Brak konfiguracji Google (Email lub Klucz)."
      );
    }

    const auth = new google.auth.GoogleAuth({
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

    const sheets = google.sheets({
      version: "v4",
      auth,
    });

    // =====================================================
    // 5. Pobranie istniejących danych
    //
    // C = data
    // F = kontrahent
    // G = kwota
    // H = numer faktury
    // K = ksefNumber
    // L = permanentStorageDate
    // =====================================================
    const existingKsefNumbers =
      new Set();

    const existingLegacyKeys =
      new Set();

    let lastPermanentStorageDate =
      null;

    try {
      const existingData =
        await sheets.spreadsheets.values.get(
          {
            spreadsheetId: sheetId,
            range: "Arkusz1!C:L",
          }
        );

      const rows =
        existingData.data.values || [];

      for (const row of rows) {
        /*
          Zakres C:L daje:

          row[0] = C = data
          row[1] = D
          row[2] = E
          row[3] = F = kontrahent
          row[4] = G = kwota
          row[5] = H = numer faktury
          row[6] = I
          row[7] = J
          row[8] = K = ksefNumber
          row[9] = L = permanentStorageDate
        */

        const issueDate = String(
          row[0] || ""
        )
          .trim()
          .replace(/^'/, "");

        const sellerName = String(
          row[3] || ""
        ).trim();

        const grossAmount =
          row[4];

        const invoiceNumber =
          String(row[5] || "").trim();

        const ksefNumber =
          String(row[8] || "").trim();

        const permanentStorageDate =
          String(row[9] || "").trim();

        // -------------------------------------------------
        // Główny identyfikator KSeF
        // -------------------------------------------------
        if (ksefNumber) {
          existingKsefNumbers.add(
            ksefNumber
          );
        }

        // -------------------------------------------------
        // Zabezpieczenie starych rekordów
        // -------------------------------------------------
        if (
          invoiceNumber &&
          issueDate
        ) {
          const legacyKey =
            createLegacyKey({
              invoiceNumber,
              issueDate,
              sellerName,
              grossAmount,
            });

          existingLegacyKeys.add(
            legacyKey
          );
        }

        // -------------------------------------------------
        // Ostatnia data PermanentStorage
        // -------------------------------------------------
        if (
          permanentStorageDate
        ) {
          const parsedDate =
            new Date(
              permanentStorageDate
            );

          if (
            !Number.isNaN(
              parsedDate.getTime()
            )
          ) {
            if (
              !lastPermanentStorageDate ||
              parsedDate >
                lastPermanentStorageDate
            ) {
              lastPermanentStorageDate =
                parsedDate;
            }
          }
        }
      }
    } catch (e) {
      console.warn(
        "Nie udało się pobrać historii arkusza:",
        e.message
      );
    }

    // =====================================================
    // 6. Uwierzytelnienie KSeF
    // =====================================================
    const accessToken =
      await authenticateKsef(
        nipFirmy
      );

    // =====================================================
    // 7. Ustalenie początku synchronizacji
    // =====================================================
    const teraz =
      new Date();

    let poczatekOkresu;

    if (
      lastPermanentStorageDate
    ) {
      poczatekOkresu =
        lastPermanentStorageDate;

      console.log(
        "Synchronizacja przyrostowa od:",
        poczatekOkresu.toISOString()
      );
    } else {
      // Pierwsza synchronizacja:
      // pierwszy dzień poprzedniego miesiąca
      poczatekOkresu =
        new Date(
          teraz.getFullYear(),
          teraz.getMonth() - 1,
          1,
          0,
          0,
          0,
          0
        );

      console.log(
        "Brak poprzedniej daty synchronizacji.",
        "Pierwszy import od:",
        poczatekOkresu.toISOString()
      );
    }

    // =====================================================
    // Maksymalnie 3 miesiące zakresu
    // =====================================================
    const trzyMiesiaceTemu =
      new Date(teraz);

    trzyMiesiaceTemu.setMonth(
      trzyMiesiaceTemu.getMonth() - 3
    );

    if (
      poczatekOkresu <
      trzyMiesiaceTemu
    ) {
      console.warn(
        "Ostatnia synchronizacja jest starsza niż 3 miesiące."
      );

      poczatekOkresu =
        trzyMiesiaceTemu;
    }

    let fromISO =
      poczatekOkresu.toISOString();

    const toISO =
      teraz.toISOString();

    // =====================================================
    // 8. Pobieranie faktur z KSeF
    // =====================================================
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

      const syncRes =
        await fetch(url, {
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

              from: fromISO,

              to: toISO,

              restrictToPermanentStorageHwmDate:
                true,
            },
          }),
        });

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

      console.log(
        `KSeF: pobrano stronę. ` +
          `offset=${pageOffset}, ` +
          `faktur=${invoices.length}, ` +
          `hasMore=${hasMore}, ` +
          `isTruncated=${isTruncated}`
      );

      // ---------------------------------------------------
      // Kolejna strona
      // ---------------------------------------------------
      if (
        hasMore &&
        !isTruncated
      ) {
        pageOffset += 250;
        continue;
      }

      // ---------------------------------------------------
      // Wynik obcięty
      // ---------------------------------------------------
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

        fromISO =
          lastDate;

        pageOffset = 0;

        console.log(
          "KSeF: wynik ucięty. Kontynuuję od:",
          fromISO
        );

        continue;
      }

      break;
    }

    // =====================================================
    // 9. Deduplikacja i przygotowanie danych
    // =====================================================
    const newInvoicesToAppend =
      [];

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

    const seenLegacyKeys =
      new Set();

    for (const inv of allInvoices) {
      // ---------------------------------------------------
      // Dane faktury
      // ---------------------------------------------------
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

      const permanentStorageDate =
        inv.permanentStorageDate
          ? String(
              inv.permanentStorageDate
            ).trim()
          : "";

      const sellerName =
        inv.seller?.name ||
        inv.seller?.nip ||
        "Brak nazwy";

      // ---------------------------------------------------
      // Bez tych danych nie możemy poprawnie zapisać
      // faktury.
      // ---------------------------------------------------
      if (
        !ksefNumber ||
        !invoiceNumber
      ) {
        console.warn(
          "Pominięto fakturę bez ksefNumber lub invoiceNumber:",
          inv
        );

        continue;
      }

      // ---------------------------------------------------
      // 1. Deduplikacja po ksefNumber
      // ---------------------------------------------------
      if (
        existingKsefNumbers.has(
          ksefNumber
        )
      ) {
        continue;
      }

      if (
        seenKsefNumbers.has(
          ksefNumber
        )
      ) {
        continue;
      }

      // ---------------------------------------------------
      // 2. Kwota
      // ---------------------------------------------------
      const grossAmount =
        typeof inv.grossAmount ===
        "number"
          ? inv.grossAmount
          : parseFloat(
              inv.grossAmount || 0
            );

      // ---------------------------------------------------
      // 3. Zabezpieczenie starych danych
      // ---------------------------------------------------
      const legacyKey =
        createLegacyKey({
          invoiceNumber,
          issueDate,
          sellerName,
          grossAmount,
        });

      if (
        existingLegacyKeys.has(
          legacyKey
        )
      ) {
        continue;
      }

      if (
        seenLegacyKeys.has(
          legacyKey
        )
      ) {
        continue;
      }

      // ---------------------------------------------------
      // 4. Miesiąc
      // ---------------------------------------------------
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
          !isNaN(
            miesiacNum
          ) &&
          miesiacNum >= 1 &&
          miesiacNum <= 12
        ) {
          miesiacFormat =
            nazwyMiesiecy[
              miesiacNum - 1
            ];
        }
      }

      // ---------------------------------------------------
      // 5. Kwota brutto
      // ---------------------------------------------------
      const kwotaBrutto =
        Number.isFinite(
          grossAmount
        )
          ? grossAmount
              .toFixed(2)
              .replace(".", ",")
          : "0,00";

      // ---------------------------------------------------
      // 6. Dodanie rekordu
      //
      // B = miesiąc
      // C = data
      // D = konto kosztowe
      // E = subkonto
      // F = nazwa wydatku
      // G = kwota
      // H = numer faktury
      // I = sposób płatności
      // J = faktura/paragon
      // K = ksefNumber
      // L = permanentStorageDate
      // M = puste
      // ---------------------------------------------------
      newInvoicesToAppend.push([
        miesiacFormat,        // B
        `'${issueDate}`,      // C
        "",                   // D
        "",                   // E
        sellerName,           // F
        kwotaBrutto,          // G
        invoiceNumber,        // H
        "przelew",            // I
        "Faktura jest",       // J
        ksefNumber,           // K
        permanentStorageDate, // L
        "",                   // M
      ]);

      // ---------------------------------------------------
      // Aktualizacja zbiorów
      // ---------------------------------------------------
      existingKsefNumbers.add(
        ksefNumber
      );

      seenKsefNumbers.add(
        ksefNumber
      );

      existingLegacyKeys.add(
        legacyKey
      );

      seenLegacyKeys.add(
        legacyKey
      );
    }

    // =====================================================
    // 10. Zapis do Google Sheets
    // =====================================================
    if (
      newInvoicesToAppend.length > 0
    ) {
      await sheets.spreadsheets.values.append(
        {
          spreadsheetId:
            sheetId,

          range:
            "Arkusz1!B:M",

          valueInputOption:
            "USER_ENTERED",

          insertDataOption:
            "INSERT_ROWS",

          requestBody: {
            values:
              newInvoicesToAppend,
          },
        }
      );
    }

    // =====================================================
    // 11. Ukrycie kolumn niepotrzebnych pracownikowi
    //
    // Widoczne:
    // B, C, F, G, H
    //
    // Ukryte:
    // A, D, E, I, J, K, L, M
    // =====================================================
    await hideNonEssentialColumns(
      sheets,
      sheetId
    );

    // =====================================================
    // 12. Odpowiedź
    // =====================================================
    return NextResponse.json({
      success: true,

      added:
        newInvoicesToAppend.length,

      fetched:
        allInvoices.length,

      message:
        `Znaleziono faktur w KSeF: ${allInvoices.length}. ` +
        `Dodano nowych: ${newInvoicesToAppend.length}.`,
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