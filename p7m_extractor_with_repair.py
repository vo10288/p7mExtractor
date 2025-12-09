#!/usr/bin/env python3
"""
P7M to PDF Extractor - Versione con riparazione automatica usando qpdf
"""

import argparse
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from asn1crypto import cms


def extract_pdf_raw(p7m_data):
    """
    Estrae il PDF cercando i marker %PDF e %%EOF nei byte raw
    """
    try:
        pdf_start = p7m_data.find(b'%PDF')
        if pdf_start == -1:
            return None
        
        pdf_end = p7m_data.rfind(b'%%EOF')
        if pdf_end == -1:
            return None
        
        pdf_end += 5
        pdf_content = p7m_data[pdf_start:pdf_end]
        
        if len(pdf_content) > 100 and pdf_content[:4] == b'%PDF':
            return pdf_content
        
        return None
    except Exception as e:
        return None


def repair_pdf_with_qpdf(input_path, output_path):
    """
    Ripara un PDF usando qpdf (se disponibile)
    
    Returns:
        (success, message)
    """
    try:
        # Verifica se qpdf è installato
        result = subprocess.run(
            ['qpdf', '--version'],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode != 0:
            return False, "qpdf non disponibile"
        
        # Ripara il PDF
        result = subprocess.run(
            [
                'qpdf',
                '--replace-input',
                '--normalize-content=y',
                '--decode-level=all',
                str(input_path),
                str(output_path)
            ],
            capture_output=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return True, "Riparato con qpdf"
        else:
            # Anche se qpdf dà warning, se l'output esiste è ok
            if output_path.exists():
                return True, "Riparato con qpdf (con warning)"
            return False, f"qpdf error: {result.stderr.decode()[:100]}"
            
    except FileNotFoundError:
        return False, "qpdf non installato"
    except Exception as e:
        return False, f"Errore qpdf: {str(e)}"


def extract_and_repair_p7m(p7m_file_path, output_base_dir, use_qpdf=True):
    """
    Estrae il PDF dal p7m e lo ripara automaticamente
    """
    try:
        # Leggi il file p7m
        with open(p7m_file_path, 'rb') as f:
            p7m_data = f.read()
        
        # Parse del contenuto PKCS#7
        content_info = cms.ContentInfo.load(p7m_data)
        content_type = content_info['content_type'].native
        
        signed_data = None
        if content_type == 'signed_data':
            signed_data = content_info['content']
        elif content_type == '1.2.840.113549.1.9.16.1.31':
            signed_data = content_info['content']
        else:
            return False, None, None, f"Tipo non supportato: {content_type}"
        
        # Estrai il PDF (metodo raw)
        pdf_content = extract_pdf_raw(p7m_data)
        
        if pdf_content is None:
            return False, None, None, "Impossibile estrarre il PDF"
        
        if not pdf_content.startswith(b'%PDF'):
            return False, None, None, "Il contenuto estratto non è un PDF valido"
        
        # Crea directory di output
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = output_base_dir / timestamp
        pdf_dir = output_dir / "pdf"
        repaired_dir = output_dir / "pdf_repaired"
        signed_dir = output_dir / "signed"
        
        pdf_dir.mkdir(parents=True, exist_ok=True)
        repaired_dir.mkdir(parents=True, exist_ok=True)
        signed_dir.mkdir(parents=True, exist_ok=True)
        
        original_filename = Path(p7m_file_path).stem
        
        # Salva il PDF originale
        pdf_original_path = pdf_dir / f"{original_filename}"
        if not pdf_original_path.suffix:
            pdf_original_path = pdf_dir / f"{original_filename}.pdf"
        
        with open(pdf_original_path, 'wb') as f:
            f.write(pdf_content)
        
        # Ripara il PDF
        pdf_repaired_path = repaired_dir / pdf_original_path.name
        repair_success = False
        repair_message = ""
        
        if use_qpdf:
            repair_success, repair_message = repair_pdf_with_qpdf(
                pdf_original_path, 
                pdf_repaired_path
            )
        
        # Se qpdf non funziona, copia comunque il file
        if not repair_success:
            with open(pdf_repaired_path, 'wb') as f:
                f.write(pdf_content)
            repair_message = "Copiato senza riparazione"
        
        # Estrai info firma (opzionale, se fallisce non è critico)
        signature_info = []
        signature_info.append(f"File P7M: {p7m_file_path}\n")
        signature_info.append(f"Data estrazione: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        signature_info.append(f"Tipo firma: CAdES (PDF estratto da struttura raw)\n")
        signature_info.append(f"Dimensione PDF: {len(pdf_content)} bytes ({len(pdf_content)/1024:.2f} KB)\n")
        signature_info.append(f"Riparazione: {repair_message}\n")
        signature_info.append("=" * 80 + "\n\n")
        
        try:
            if signed_data and hasattr(signed_data, '__getitem__'):
                certificates = signed_data.get('certificates')
                if certificates:
                    signature_info.append(f"Certificati trovati: {len(certificates)}\n")
        except:
            pass
        
        # Salva info firma
        signature_output_path = signed_dir / f"{Path(original_filename).stem}_info.txt"
        with open(signature_output_path, 'w', encoding='utf-8') as f:
            f.writelines(signature_info)
        
        return True, pdf_repaired_path, signature_output_path, repair_message
        
    except Exception as e:
        import traceback
        return False, None, None, f"{str(e)}"


def process_directory(input_dir, output_base_dir, use_qpdf=True):
    """
    Processa tutti i file p7m in una directory
    """
    input_path = Path(input_dir)
    output_path = Path(output_base_dir)
    
    if not input_path.exists():
        print(f"❌ Errore: La directory {input_dir} non esiste")
        return
    
    if not input_path.is_dir():
        print(f"❌ Errore: {input_dir} non è una directory")
        return
    
    # Trova tutti i file p7m
    p7m_files = list(input_path.glob("*.p7m"))
    
    if not p7m_files:
        print(f"⚠️  Nessun file .p7m trovato in {input_dir}")
        return
    
    # Verifica disponibilità qpdf
    qpdf_available = False
    if use_qpdf:
        try:
            result = subprocess.run(
                ['qpdf', '--version'],
                capture_output=True,
                timeout=5
            )
            qpdf_available = (result.returncode == 0)
            if qpdf_available:
                print(f"✅ qpdf disponibile - verrà usato per riparare i PDF")
            else:
                print(f"⚠️  qpdf non disponibile - i PDF non verranno riparati")
                print(f"   Installa qpdf con: apt install qpdf (Linux) o brew install qpdf (Mac)")
        except:
            print(f"⚠️  qpdf non trovato - i PDF non verranno riparati")
            use_qpdf = False
    
    print(f"\n📁 Trovati {len(p7m_files)} file p7m da processare\n")
    
    success_count = 0
    error_count = 0
    errors_detail = []
    
    for p7m_file in p7m_files:
        print(f"🔄 Processando: {p7m_file.name}...", end=" ", flush=True)
        
        success, pdf_path, sig_path, message = extract_and_repair_p7m(
            p7m_file, output_path, use_qpdf and qpdf_available
        )
        
        if success:
            print(f"✅ {message}")
            success_count += 1
        else:
            print(f"❌")
            error_count += 1
            errors_detail.append(f"  - {p7m_file.name}: {message}")
    
    print(f"\n{'='*80}")
    print(f"✅ Processati con successo: {success_count}")
    print(f"❌ Errori: {error_count}")
    
    if errors_detail:
        print(f"\n⚠️  Dettaglio errori:")
        for err in errors_detail:
            print(err)
    
    if success_count > 0:
        print(f"\n📂 File estratti salvati in: {output_path}")
        print(f"\nStruttura creata:")
        print(f"  {output_path}/TIMESTAMP/")
        print(f"  ├── pdf/              (PDF originali estratti)")
        print(f"  ├── pdf_repaired/     (PDF riparati - USARE QUESTI)")
        print(f"  └── signed/           (informazioni firme)")


def main():
    parser = argparse.ArgumentParser(
        description="Estrae e ripara PDF da file p7m",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Questo script estrae i PDF dai file p7m e li ripara automaticamente
usando qpdf per risolvere problemi con font e struttura.

Installazione qpdf:
  Ubuntu/Debian: sudo apt install qpdf
  macOS: brew install qpdf
  Windows: scoop install qpdf

Esempi:
  %(prog)s -i ./documenti_p7m
  %(prog)s -i ./documenti_p7m --no-repair
        """
    )
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Directory contenente i file p7m'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='./output',
        help='Directory di output (default: ./output)'
    )
    
    parser.add_argument(
        '--no-repair',
        action='store_true',
        help='Non usare qpdf per riparare i PDF'
    )
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("P7M EXTRACTOR + PDF REPAIR")
    print("Estrazione e riparazione automatica PDF da file p7m")
    print("=" * 80)
    print()
    
    process_directory(args.input, args.output, use_qpdf=not args.no_repair)


if __name__ == "__main__":
    main()
