import { NextResponse } from 'next/server';
import { google } from 'googleapis';
import crypto from 'crypto';

// Ustawienia środowiska KSeF (Zmień na 'https://ksef-test.mf.gov.pl/api' jeśli używasz dema)
const KSEF_BASE_URL = 'https://ksef.mf.gov.pl/api';

export async function POST(request) {
  try {
    const body = await request.json();
    const { secretKey, sheetId } = body;

    // 1. Weryfikacja hasła
    if (secretKey !== process.env.API_SECRET_KEY) {
      return NextResponse.json({ error: "Odmowa dostępu. Nieprawidłowy klucz API." }, { status: 401 });
    }

    // 2. Połączenie z Google Sheets API
    const auth = new google.auth.GoogleAuth({
      credentials: {
        client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
        private_key: (process.env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, '\n'),
      },
      scopes: ['https://www.googleapis.com/auth/spreadsheets'],
    });
    const sheets = google.sheets({ version: 'v4', auth });

    // 3. Pobranie istniejących faktur z Arkusza (Kolumna H), aby uniknąć duplikatów
    let existingInvoiceNumbers = new Set();
    try {
      const existingData = await sheets.spreadsheets.values.get({
        spreadsheetId: sheetId,
        range: 'Arkusz1!H:H', // Zakładamy, że kolumna H to numery faktur
      });
      const rows = existingData.data.values;
      if (rows && rows.length > 0) {
        existingInvoiceNumbers = new Set(rows.map(row => row[0]).filter(Boolean));
      }
    } catch (e) {
      console.warn("Nie udało się pobrać istniejących danych (może pusty arkusz):", e.message);
    }

    // 4. AUTORYZACJA W KSEF (Zarys logiki kryptograficznej)
    // UWAGA: KSeF wymaga klucza publicznego MF do zaszyfrowania tokena. 
    // W pełnym wdrożeniu ten blok wykonuje RSA-OAEP z użyciem klucza środowiska.
    
    // a) Pobranie wyzwania (Challenge)
    const challengeRes = await fetch(`${KSEF_BASE_URL}/online/Session/AuthorisationChallenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contextIdentifier: { type: 'onip', identifier: process.env.NIP_FIRMY }
      })
    });
    if (!challengeRes.ok) throw new Error("Błąd pobierania wyzwania KSeF");
    const challengeData = await challengeRes.json();
    
    /* 
      --- MIEJSCE NA KRYPTOGRAFIĘ RSA ---
      Tutaj następuje zaszyfrowanie: Encrypt(KSEF_TOKEN | challengeData.timestamp)
      i wysłanie do endpointu /online/Session/InitToken w celu uzyskania SessionToken.
    */
    const sessionToken = "MOCK_SESSION_TOKEN"; // Zastąpić prawdziwym tokenem z bloku wyżej

    // 5. Pobranie faktur z KSeF (Query Sync)
    // Ustawiamy daty: np. od początku bieżącego miesiąca
    const dzisiaj = new Date();
    const poczatekMiesiaca = new Date(dzisiaj.getFullYear(), dzisiaj.getMonth(), 1).toISOString();
    const teraz = dzisiaj.toISOString();

    /*
      const syncRes = await fetch(`${KSEF_BASE_URL}/online/Query/Invoice/Sync`, {
        method: 'POST',
        headers: { 'SessionToken': sessionToken, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          queryCriteria: {
            subjectType: "subject2", // subject2 = faktury kosztowe (nabywca)
            type: "incremental",
            acquisitionTimestampThresholdFrom: poczatekMiesiaca,
            acquisitionTimestampThresholdTo: teraz
          }
        })
      });
      const invoicesData = await syncRes.json();
      const fetchedInvoices = invoicesData.invoiceHeaderList || [];
    */

    // MOCK: Symulacja danych zwróconych przez KSeF dla celów demonstracji mechanizmu
    const fetchedInvoices = [
      { invoiceNumber: "TEST/API/2026", net: "100", vat: "23", subjectTo: { name: "Stary Kontrahent" }, invoicingDate: "2026-09-01" },
      { invoiceNumber: "FV/123/NOWA", net: "500", vat: "115", subjectTo: { name: "Nowy Kontrahent Sp. z o.o." }, invoicingDate: "2026-09-02" }
    ];

    // 6. FILTROWANIE DUPLIKATÓW
    const newInvoicesToAppend = [];
    
    for (const inv of fetchedInvoices) {
      if (!existingInvoiceNumbers.has(inv.invoiceNumber)) {
        // Mapowanie na kolumny A-M
        const miesiac = inv.invoicingDate.substring(5, 7); // np. "09"
        const kwotaBrutto = (parseFloat(inv.net) + parseFloat(inv.vat)).toFixed(2).replace('.', ',');

        newInvoicesToAppend.push([
          "", // A
          miesiac, // B
          inv.invoicingDate, // C
          "", "", // D, E
          inv.subjectTo.name, // F
          kwotaBrutto, // G
          inv.invoiceNumber, // H (Klucz do duplikatów)
          "przelew", "Faktura jest", "", "", "" // I, J, K, L, M
        ]);
      }
    }

    // 7. Zapis do Arkusza (Tylko jeśli są nowe faktury)
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
      message: `Pobrano pomyślnie. Dodano nowych faktur: ${newInvoicesToAppend.length}`,
    });

  } catch (error) {
    console.error("Wystąpił błąd krytyczny:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}