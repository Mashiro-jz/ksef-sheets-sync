import { NextResponse } from 'next/server';
import { google } from 'googleapis';
import crypto from 'crypto';

// Zmień na 'https://ksef-test.mf.gov.pl/api' jeśli to środowisko testowe
const KSEF_BASE_URL = 'https://ksef.mf.gov.pl/v2';

export async function POST(request) {
  try {
    const body = await request.json();
    const { secretKey, sheetId } = body;

    // 1. Zabezpieczenie
    if (secretKey !== process.env.API_SECRET_KEY) {
      return NextResponse.json({ error: "Odmowa dostępu. Nieprawidłowy klucz." }, { status: 401 });
    }

    const nipFirmy = (process.env.NIP_FIRMY || "").replace(/\D/g, '');

    // 2. Połączenie z Google Sheets
    const auth = new google.auth.GoogleAuth({
      credentials: {
        client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
        private_key: (process.env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, '\n'),
      },
      scopes: ['https://www.googleapis.com/auth/spreadsheets'],
    });
    const sheets = google.sheets({ version: 'v4', auth });

    // 3. Pobranie istniejących faktur (Deduplikacja)
    let existingInvoiceNumbers = new Set();
    try {
      const existingData = await sheets.spreadsheets.values.get({
        spreadsheetId: sheetId,
        range: 'Arkusz1!H:H',
      });
      const rows = existingData.data.values;
      if (rows && rows.length > 0) {
        existingInvoiceNumbers = new Set(rows.map(row => row[0]).filter(Boolean));
      }
    } catch (e) {
      console.warn("Brak historii:", e.message);
    }

    // 4. Pobranie Challenge'u KSeF
    const challengeRes = await fetch(`${KSEF_BASE_URL}/online/Session/AuthorisationChallenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ contextIdentifier: { type: 'onip', identifier: nipFirmy } })
    });
    
    const challengeText = await challengeRes.text();
    let challengeData;
    try { challengeData = JSON.parse(challengeText); } catch (e) { throw new Error(`Błąd Challenge: ${challengeText.substring(0, 100)}`); }
    if (!challengeRes.ok) throw new Error(`KSeF Odrzucił Challenge: ${challengeData.exception?.exceptionDetailList?.[0]?.exceptionMessage}`);

    // 5. AUTOMATYCZNE POBRANIE I KONWERSJA CERTYFIKATU (Zastępuje OpenSSL)
    const certRes = await fetch(`${KSEF_BASE_URL}/common/Files/PublicKey`);
    if (!certRes.ok) throw new Error("Nie udało się pobrać certyfikatu publicznego MF.");
    const certBuffer = await certRes.arrayBuffer();
    
    // Konwersja formatu DER (binarnego) na Base64 i formatowanie do standardu PEM
    const certBase64 = Buffer.from(certBuffer).toString('base64');
    const publicKeyPem = `-----BEGIN CERTIFICATE-----\n${certBase64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

    // 6. SZYFROWANIE TOKENA
    const timestamp = challengeData.timestamp;
    const challengeToken = challengeData.challenge;
    const authMessage = `${process.env.KSEF_TOKEN}|${timestamp}`;
    
    const encryptedToken = crypto.publicEncrypt(
      { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PADDING },
      Buffer.from(authMessage, 'utf8')
    ).toString('base64');

    // 7. LOGOWANIE (InitToken)
    const initSessionRes = await fetch(`${KSEF_BASE_URL}/online/Session/InitToken`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        contextIdentifier: { type: 'onip', identifier: nipFirmy },
        challengeReferenceNumber: challengeToken,
        sessionToken: {
          token: encryptedToken,
          contextIdentifier: { type: 'onip', identifier: nipFirmy }
        }
      })
    });

    const sessionText = await initSessionRes.text();
    let sessionData;
    try { sessionData = JSON.parse(sessionText); } catch (e) { throw new Error(`Błąd logowania: ${sessionText.substring(0, 100)}`); }
    if (!initSessionRes.ok) throw new Error(`KSeF InitToken Błąd: ${sessionData.exception?.exceptionDetailList?.[0]?.exceptionMessage}`);
    
    const sessionToken = sessionData.sessionToken.token;

    // 8. POBRANIE FAKTUR KOSZTOWYCH (Od początku miesiąca)
    const dzisiaj = new Date();
    const poczatekMiesiaca = new Date(dzisiaj.getFullYear(), dzisiaj.getMonth(), 1).toISOString();
    const teraz = dzisiaj.toISOString();

    const syncRes = await fetch(`${KSEF_BASE_URL}/online/Query/Invoice/Sync`, {
      method: 'POST',
      headers: { 'SessionToken': sessionToken, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        queryCriteria: {
          subjectType: "subject2", // Nabywca
          type: "incremental",
          acquisitionTimestampThresholdFrom: poczatekMiesiaca,
          acquisitionTimestampThresholdTo: teraz
        }
      })
    });

    const syncText = await syncRes.text();
    let syncData;
    try { syncData = JSON.parse(syncText); } catch (e) { throw new Error(`Błąd pobierania list: ${syncText.substring(0, 100)}`); }
    
    // Zamknięcie sesji w tle
    fetch(`${KSEF_BASE_URL}/online/Session/Terminate`, { headers: { 'SessionToken': sessionToken, 'Accept': 'application/json' } }).catch(()=>{});

    if (!syncRes.ok) throw new Error(`Błąd z KSeF: ${syncData.exception?.exceptionDetailList?.[0]?.exceptionMessage}`);

    const fetchedInvoices = syncData.invoiceHeaderList || [];

    // 9. FILTROWANIE I ZAPIS
    const newInvoicesToAppend = [];
    for (const inv of fetchedInvoices) {
      if (!existingInvoiceNumbers.has(inv.invoiceReferenceNumber)) {
        const miesiac = inv.invoicingDate.substring(5, 7); 
        const kwotaBrutto = (parseFloat(inv.net || 0) + parseFloat(inv.vat || 0)).toFixed(2).replace('.', ',');

        newInvoicesToAppend.push([
          "", miesiac, inv.invoicingDate, "", "",
          inv.subjectTo?.name || "Brak nazwy",
          kwotaBrutto,
          inv.invoiceReferenceNumber,
          "przelew", "Faktura jest", "", "", ""
        ]);
      }
    }

    if (newInvoicesToAppend.length > 0) {
      await sheets.spreadsheets.values.append({
        spreadsheetId: sheetId,
        range: 'Arkusz1!A2:M',
        valueInputOption: 'USER_ENTERED',
        requestBody: { values: newInvoicesToAppend },
      });
    }

    return NextResponse.json({
      success: true,
      added: newInvoicesToAppend.length,
      message: `Pobrano pomyślnie. Nowe faktury: ${newInvoicesToAppend.length}`,
    });

  } catch (error) {
    console.error("Wystąpił błąd krytyczny:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}