import { NextResponse } from 'next/server';
import { google } from 'googleapis';

export async function POST(request) {
  try {
    const body = await request.json();
    const { secretKey, sheetId } = body;

    // 1. Zabezpieczenie przed intruzami
    if (secretKey !== process.env.API_SECRET_KEY) {
      return NextResponse.json({ error: "Odmowa dostępu. Nieprawidłowy klucz." }, { status: 401 });
    }

    // 2. Konfiguracja logowania bota do Google
    const auth = new google.auth.GoogleAuth({
      credentials: {
        client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
        // Replace naprawia problem ze znakami nowej linii w zmiennych środowiskowych
        private_key: (process.env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, '\n'),
      },
      scopes: ['https://www.googleapis.com/auth/spreadsheets'],
    });

    const sheets = google.sheets({ version: 'v4', auth });

    // 3. Przygotowanie wiersza testowego (zgodnie z Twoimi kolumnami z Excela)
    const testRow = [
      "", // A (Puste)
      "09 (WRZ)", // B (miesiac)
      "2026-09-01", // C (data)
      "", "", // D, E (Konta)
      "Wpis Testowy z API", // F (Nazwa wydatku)
      "999,00", // G (Kwota brutto)
      "TEST/API/2026", // H (uwagi / nr faktury)
      "przelew", "Faktura jest", "", "", "" // I, J, K, L, M
    ];

    // 4. Wypchnięcie danych do arkusza
    const response = await sheets.spreadsheets.values.append({
      spreadsheetId: sheetId,
      range: 'Arkusz1!A2:M', // WAŻNE: Jeśli Twoja zakładka na dole ekranu nazywa się inaczej niż "Arkusz1", zmień to tutaj!
      valueInputOption: 'USER_ENTERED',
      requestBody: {
        values: [testRow],
      },
    });

    return NextResponse.json({
      success: true,
      message: "Testowy wiersz dodany pomyślnie!",
    });

  } catch (error) {
    console.error("Wystąpił błąd krytyczny:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}