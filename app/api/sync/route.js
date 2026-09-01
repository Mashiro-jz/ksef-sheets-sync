import { NextResponse } from 'next/server';
import { google } from 'googleapis';
import crypto from 'crypto';

// Oficjalny bazowy adres API v2 KSeF
const KSEF_BASE_URL = 'https://api.ksef.mf.gov.pl/v2';

export async function POST(request) {
  try {
    const body = await request.json();
    const { secretKey, sheetId } = body;

    if (secretKey !== process.env.API_SECRET_KEY) {
      return NextResponse.json({ error: "Odmowa dostępu. Nieprawidłowy klucz." }, { status: 401 });
    }

    const nipFirmy = (process.env.NIP_FIRMY || "").replace(/\D/g, '');

    const auth = new google.auth.GoogleAuth({
      credentials: {
        client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
        private_key: (process.env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, '\n'),
      },
      scopes: ['https://www.googleapis.com/auth/spreadsheets'],
    });
    const sheets = google.sheets({ version: 'v4', auth });

    // 1. Pobranie istniejących faktur (Deduplikacja)
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

    // 2. KSeF v2: Poprawny endpoint pobierania Challenge (/auth/challenge)
    const challengeRes = await fetch(`${KSEF_BASE_URL}/auth/challenge`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Error-Format': 'problem-details'
      },
      body: JSON.stringify({
        contextIdentifier: {
          type: "onip",
          identifier: nipFirmy
        }
      })
    });
    
    const challengeText = await challengeRes.text();
    let challengeData;
    try { 
      challengeData = JSON.parse(challengeText); 
    } catch (e) { 
      throw new Error(`KSeF v2 zwrócił HTML przy Challenge: ${challengeText.substring(0, 120)}`); 
    }
    
    if (!challengeRes.ok) {
      throw new Error(`KSeF Challenge Błąd: ${challengeData.title || challengeData.detail || challengeRes.statusText}`);
    }

    const timestamp = challengeData.timestamp;
    const challengeToken = challengeData.challenge;

    // 3. Pobranie certyfikatu publicznego MF dla v2
    const certRes = await fetch(`${KSEF_BASE_URL}/security/public-key-certificates`);
    if (!certRes.ok) throw new Error("Nie udało się pobrać certyfikatów publicznych KSeF v2.");
    const certsJson = await certRes.json();
    
    // Pobieramy pierwszy certyfikat z listy
    const base64DerCert = certsJson[0]?.certificate;
    if (!base64DerCert) throw new Error("Brak certyfikatu w odpowiedzi KSeF v2.");

    const publicKeyPem = `-----BEGIN CERTIFICATE-----\n${base64DerCert.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

    // 4. Szyfrowanie tokena (KSeF Token + Timestamp)
    const authMessage = `${process.env.KSEF_TOKEN}|${timestamp}`;
    const encryptedToken = crypto.publicEncrypt(
      { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PADDING },
      Buffer.from(authMessage, 'utf8')
    ).toString('base64');

    // 5. KSeF v2: Uwierzytelnienie za pomocą tokena (/auth/ksef-token)
    const authKsefRes = await fetch(`${KSEF_BASE_URL}/auth/ksef-token`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Error-Format': 'problem-details'
      },
      body: JSON.stringify({
        challenge: challengeToken,
        contextIdentifier: {
          type: "onip",
          identifier: nipFirmy
        },
        encryptedToken: encryptedToken
      })
    });

    const authText = await authKsefRes.text();
    let authData;
    try { authData = JSON.parse(authText); } catch (e) { throw new Error(`Błąd uwierzytelniania JSON: ${authText.substring(0, 100)}`); }
    if (!authKsefRes.ok) throw new Error(`KSeF Auth Błąd: ${authData.title || authData.detail || authText}`);
    
    const referenceNumber = authData.referenceNumber;

    // 6. Oczekiwanie / pobranie statusu i tokena sesyjnego (accessToken / authenticationToken)
    // W KSeF v2 po wysłaniu żądania dostajemy referenceNumber, sprawdzamy status i odbieramy token dostępu
    let accessToken = null;
    for (let i = 0; i < 3; i++) {
      await new Promise(res => setTimeout(res, 2000)); // Czekaj 2 sekundy na przetworzenie po stronie MF
      
      const statusRes = await fetch(`${KSEF_BASE_URL}/auth/${referenceNumber}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      
      if (statusRes.ok) {
        const statusData = await statusRes.json();
        // Jeśli status gotowy, wyciągamy token
        if (statusData.status?.code === 200 || statusData.accessToken) {
          accessToken = statusData.accessToken || statusData.authenticationToken;
          break;
        }
      }
    }

    if (!accessToken && authData.accessToken) {
      accessToken = authData.accessToken;
    }
    if (!accessToken) {
      accessToken = authData.authenticationToken || referenceNumber; // Fallback
    }

    // 7. Pobranie faktur kosztowych (API v2)
    const dzisiaj = new Date();
    const poczatekMiesiaca = new Date(dzisiaj.getFullYear(), dzisiaj.getMonth(), 1).toISOString();
    const teraz = dzisiaj.toISOString();

    const syncRes = await fetch(`${KSEF_BASE_URL}/online/Query/Invoice/Sync`, {
      method: 'POST',
      headers: { 
        'SessionToken': accessToken, 
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json', 
        'Accept': 'application/json' 
      },
      body: JSON.stringify({
        queryCriteria: {
          subjectType: "subject2",
          type: "incremental",
          acquisitionTimestampThresholdFrom: poczatekMiesiaca,
          acquisitionTimestampThresholdTo: teraz
        }
      })
    });

    const syncText = await syncRes.text();
    let syncData;
    try { syncData = JSON.parse(syncText); } catch (e) { throw new Error(`Błąd pobierania list: ${syncText.substring(0, 100)}`); }
    
    if (!syncRes.ok) throw new Error(`Błąd pobierania faktur KSeF: ${syncData.title || syncData.detail || syncText}`);

    const fetchedInvoices = syncData.invoiceHeaderList || [];

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