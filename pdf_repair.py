#!/usr/bin/env python3
"""
PDF Repair Tool - Ripara PDF con problemi di font e BBox
"""

import sys
from pathlib import Path
import argparse
import re


def repair_pdf(input_path, output_path):
    """
    Ripara un PDF rimuovendo o correggendo valori BBox problematici
    
    Returns:
        (success, message)
    """
    try:
        with open(input_path, 'rb') as f:
            content = f.read()
        
        # Verifica che sia un PDF
        if not content.startswith(b'%PDF'):
            return False, "Non è un file PDF valido"
        
        # Converti in stringa per manipolazione (gestendo errori)
        try:
            pdf_str = content.decode('latin-1')
        except:
            # Se non riesce, lavora con i byte
            with open(output_path, 'wb') as f:
                f.write(content)
            return True, "PDF copiato senza modifiche (contenuto binario)"
        
        # Pattern per trovare e correggere BBox problematici
        # Cerca pattern come /BBox [ valori ] e li normalizza
        
        # Sostituisci BBox con valori zero o negativi strani
        pdf_str = re.sub(
            r'/BBox\s*\[\s*-?\d+(?:\.\d+)?\s+-?\d+(?:\.\d+)?\s+-?\d+(?:\.\d+)?\s+-?\d+(?:\.\d+)?\s*\]',
            '/BBox [0 0 1000 1000]',
            pdf_str
        )
        
        # Rimuovi FontBBox problematici se presenti
        pdf_str = re.sub(
            r'/FontBBox\s*\[\s*[^\]]*\]',
            '/FontBBox [0 0 1000 1000]',
            pdf_str
        )
        
        # Salva il PDF riparato
        with open(output_path, 'wb') as f:
            f.write(pdf_str.encode('latin-1'))
        
        return True, "PDF riparato con successo"
        
    except Exception as e:
        return False, f"Errore durante la riparazione: {str(e)}"


def repair_pdf_with_pypdf(input_path, output_path):
    """
    Ripara PDF usando PyPDF (metodo alternativo più robusto)
    """
    try:
        from pypdf import PdfReader, PdfWriter
        
        reader = PdfReader(input_path, strict=False)
        writer = PdfWriter()
        
        # Copia tutte le pagine
        for page in reader.pages:
            writer.add_page(page)
        
        # Copia metadata se presenti
        if reader.metadata:
            writer.add_metadata(reader.metadata)
        
        # Salva senza compressione per evitare problemi
        with open(output_path, 'wb') as f:
            writer.write(f)
        
        return True, f"PDF riparato con PyPDF ({len(reader.pages)} pagine)"
        
    except ImportError:
        return False, "PyPDF non installato (pip install pypdf)"
    except Exception as e:
        return False, f"Errore PyPDF: {str(e)}"


def main():
    parser = argparse.ArgumentParser(
        description="Ripara PDF con problemi di font e BBox"
    )
    
    parser.add_argument(
        'input',
        help='File PDF o directory da riparare'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Directory di output (default: input_repaired)'
    )
    
    parser.add_argument(
        '--use-pypdf',
        action='store_true',
        help='Usa PyPDF per riparazione più robusta (richiede: pip install pypdf)'
    )
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    
    if not input_path.exists():
        print(f"❌ Percorso non trovato: {args.input}")
        return 1
    
    # Determina output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        if input_path.is_file():
            output_dir = input_path.parent / "repaired"
        else:
            output_dir = input_path.parent / f"{input_path.name}_repaired"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Lista di PDF da riparare
    pdf_files = []
    if input_path.is_file():
        pdf_files = [input_path]
    else:
        pdf_files = list(input_path.glob("*.pdf"))
    
    if not pdf_files:
        print(f"⚠️  Nessun file PDF trovato in {args.input}")
        return 1
    
    print(f"🔧 Riparo {len(pdf_files)} file PDF...")
    print(f"📂 Output: {output_dir}\n")
    
    success_count = 0
    error_count = 0
    
    for pdf_file in pdf_files:
        print(f"🔄 Riparando: {pdf_file.name}...", end=" ", flush=True)
        
        output_path = output_dir / pdf_file.name
        
        # Prova prima con il metodo semplice
        if args.use_pypdf:
            success, message = repair_pdf_with_pypdf(pdf_file, output_path)
        else:
            success, message = repair_pdf(pdf_file, output_path)
        
        if success:
            print(f"✅ {message}")
            success_count += 1
        else:
            print(f"❌ {message}")
            error_count += 1
    
    print(f"\n{'='*80}")
    print(f"✅ Riparati con successo: {success_count}")
    print(f"❌ Errori: {error_count}")
    print(f"\n📂 PDF riparati salvati in: {output_dir}")
    
    if not args.use_pypdf and error_count > 0:
        print(f"\n💡 Prova con --use-pypdf per una riparazione più robusta")
        print(f"   (richiede: pip install pypdf)")


if __name__ == "__main__":
    sys.exit(main())
