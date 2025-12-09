# P7M Extractor

Programma Python per estrarre massivamente PDF e informazioni sulle firme digitali da file p7m (PKCS#7 signed data).

## Caratteristiche

- ✅ Estrazione automatica del contenuto PDF da file p7m
- ✅ Estrazione completa delle informazioni sulla firma digitale
- ✅ Processamento batch di intere directory
- ✅ Output organizzato con timestamp
- ✅ Supporto per file con firme multiple
- ✅ Report dettagliati sui certificati e firmatari

## Requisiti

- Python 3.7 o superiore
- pip (gestore pacchetti Python)

## Installazione

1. Installa le dipendenze:

```bash
pip install -r requirements.txt
```

oppure manualmente:

```bash
pip install cryptography asn1crypto
```

## Utilizzo

### Sintassi base

```bash
python p7m_extractor.py -i <directory_input> [-o <directory_output>]
```

### Parametri

- `-i, --input`: **[OBBLIGATORIO]** Directory contenente i file p7m da processare
- `-o, --output`: **[OPZIONALE]** Directory di output (default: `./output`)

### Esempi

Processare tutti i file p7m in una directory:
```bash
python p7m_extractor.py -i /path/to/p7m/files
```

Specificare una directory di output personalizzata:
```bash
python p7m_extractor.py -i ./documenti_firmati -o ./documenti_estratti
```

## Struttura Output

Il programma crea una struttura organizzata con timestamp:

```
output_directory/
└── YYYYMMDD_HHMMSS/
    ├── pdf/
    │   ├── documento1.pdf
    │   ├── documento2.pdf
    │   └── documento3.pdf
    └── signed/
        ├── documento1_signature_info.txt
        ├── documento2_signature_info.txt
        └── documento3_signature_info.txt
```

### Contenuto dei file di firma

I file `*_signature_info.txt` contengono:

- Nome del file originale
- Data e ora dell'estrazione
- Informazioni sui certificati:
  - Subject (soggetto)
  - Issuer (emittente)
  - Numero seriale
  - Date di validità
  - Algoritmo di firma
- Informazioni sui firmatari:
  - Versione
  - Issuer e serial number
  - Algoritmi utilizzati (digest e firma)

## Funzionalità

### Estrazione PDF
Il programma estrae il contenuto PDF incorporato nel file p7m. I PDF estratti sono identici ai file originali prima della firma.

### Informazioni sulla Firma
Per ogni file p7m, viene generato un file di testo con tutte le informazioni sulla firma digitale, inclusi:
- Dettagli dei certificati utilizzati
- Informazioni sui firmatari
- Algoritmi crittografici utilizzati
- Date di validità

### Gestione Errori
Il programma gestisce automaticamente:
- File p7m corrotti o non validi
- Directory inesistenti
- Permessi di lettura/scrittura
- Formati non supportati

Alla fine dell'elaborazione viene mostrato un riepilogo con:
- Numero di file processati con successo
- Numero di errori riscontrati
- Percorso dei file estratti

## Note Tecniche

- Il programma supporta solo file p7m di tipo `signed_data` (non criptati)
- I file devono avere l'estensione `.p7m`
- Il contenuto estratto deve essere in formato PDF
- Supporta firme multiple sullo stesso documento

## Risoluzione Problemi

### Errore "ModuleNotFoundError"
Assicurati di aver installato tutte le dipendenze:
```bash
pip install -r requirements.txt
```

### Errore "Permission denied"
Verifica di avere i permessi di lettura sulla directory input e di scrittura sulla directory output.

### "Nessun file .p7m trovato"
Verifica che:
- La directory specificata sia corretta
- I file abbiano l'estensione `.p7m` (case-sensitive su Linux/Mac)

### File p7m criptato
Questo programma supporta solo file p7m firmati (signed), non criptati (enveloped). Se hai file criptati, devi prima decriptarli con la chiave privata appropriata.

## Licenza

Questo programma è fornito "così com'è" senza garanzie di alcun tipo.

## Supporto

Per problemi o domande, verifica:
1. Di avere installato tutte le dipendenze
2. Che i file p7m siano validi e non corrotti
3. Di avere i permessi corretti sulle directory
