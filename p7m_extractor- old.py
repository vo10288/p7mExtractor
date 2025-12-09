#!/usr/bin/env python3
"""
P7M Extractor - Estrae PDF e firme digitali da file p7m (PKCS#7)
"""

import argparse
import os
import sys
from pathlib import Path
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from asn1crypto import cms
import shutil


def extract_p7m(p7m_file_path, output_base_dir):
    """
    Estrae il contenuto PDF e le informazioni sulla firma da un file p7m
    
    Args:
        p7m_file_path: Path del file p7m da processare
        output_base_dir: Directory base dove creare le sottocartelle
    
    Returns:
        tuple: (success, pdf_path, signature_info_path, error_message)
    """
    try:
        # Leggi il file p7m
        with open(p7m_file_path, 'rb') as f:
            p7m_data = f.read()
        
        # Parse del contenuto PKCS#7
        content_info = cms.ContentInfo.load(p7m_data)
        
        if content_info['content_type'].native != 'signed_data':
            return False, None, None, f"Il file non è di tipo signed_data: {content_info['content_type'].native}"
        
        signed_data = content_info['content']
        
        # Estrai il contenuto originale (PDF)
        encap_content_info = signed_data['encap_content_info']
        pdf_content = encap_content_info['content'].native
        
        if pdf_content is None:
            return False, None, None, "Nessun contenuto incorporato trovato nel file p7m"
        
        # Nome del file senza estensione p7m
        original_filename = Path(p7m_file_path).stem
        
        # Crea directory di output con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = output_base_dir / timestamp
        pdf_dir = output_dir / "pdf"
        signed_dir = output_dir / "signed"
        
        pdf_dir.mkdir(parents=True, exist_ok=True)
        signed_dir.mkdir(parents=True, exist_ok=True)
        
        # Salva il PDF
        pdf_output_path = pdf_dir / f"{original_filename}.pdf"
        with open(pdf_output_path, 'wb') as f:
            f.write(pdf_content)
        
        # Estrai informazioni sulla firma
        signature_info = []
        signature_info.append(f"File originale: {p7m_file_path}\n")
        signature_info.append(f"Data estrazione: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        signature_info.append("=" * 80 + "\n\n")
        
        # Informazioni sui certificati
        certificates = signed_data['certificates']
        signature_info.append(f"Numero di certificati trovati: {len(certificates)}\n\n")
        
        for idx, cert_choice in enumerate(certificates, 1):
            if cert_choice.name == 'certificate':
                cert_bytes = cert_choice.chosen.dump()
                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                
                signature_info.append(f"--- CERTIFICATO {idx} ---\n")
                signature_info.append(f"Subject: {cert.subject.rfc4514_string()}\n")
                signature_info.append(f"Issuer: {cert.issuer.rfc4514_string()}\n")
                signature_info.append(f"Serial Number: {cert.serial_number}\n")
                signature_info.append(f"Valido da: {cert.not_valid_before_utc}\n")
                signature_info.append(f"Valido fino a: {cert.not_valid_after_utc}\n")
                signature_info.append(f"Algoritmo firma: {cert.signature_algorithm_oid._name}\n")
                signature_info.append("\n")
        
        # Informazioni sui firmatari
        signer_infos = signed_data['signer_infos']
        signature_info.append(f"Numero di firmatari: {len(signer_infos)}\n\n")
        
        for idx, signer_info in enumerate(signer_infos, 1):
            signature_info.append(f"--- FIRMATARIO {idx} ---\n")
            signature_info.append(f"Versione: {signer_info['version'].native}\n")
            
            sid = signer_info['sid']
            if sid.name == 'issuer_and_serial_number':
                signature_info.append(f"Issuer: {sid.chosen['issuer'].human_friendly}\n")
                signature_info.append(f"Serial Number: {sid.chosen['serial_number'].native}\n")
            
            digest_algo = signer_info['digest_algorithm']['algorithm'].native
            signature_info.append(f"Algoritmo digest: {digest_algo}\n")
            
            sig_algo = signer_info['signature_algorithm']['algorithm'].native
            signature_info.append(f"Algoritmo firma: {sig_algo}\n")
            signature_info.append("\n")
        
        # Salva le informazioni sulla firma
        signature_output_path = signed_dir / f"{original_filename}_signature_info.txt"
        with open(signature_output_path, 'w', encoding='utf-8') as f:
            f.writelines(signature_info)
        
        return True, pdf_output_path, signature_output_path, None
        
    except Exception as e:
        return False, None, None, str(e)


def process_directory(input_dir, output_base_dir):
    """
    Processa tutti i file p7m in una directory
    
    Args:
        input_dir: Directory contenente i file p7m
        output_base_dir: Directory base per l'output
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
    
    print(f"📁 Trovati {len(p7m_files)} file p7m da processare\n")
    
    success_count = 0
    error_count = 0
    
    for p7m_file in p7m_files:
        print(f"🔄 Processando: {p7m_file.name}...", end=" ")
        
        success, pdf_path, sig_path, error = extract_p7m(p7m_file, output_path)
        
        if success:
            print("✅")
            success_count += 1
        else:
            print(f"❌ Errore: {error}")
            error_count += 1
    
    print(f"\n{'='*80}")
    print(f"✅ Processati con successo: {success_count}")
    print(f"❌ Errori: {error_count}")
    print(f"📂 File estratti salvati in: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Estrae PDF e informazioni sulle firme digitali da file p7m",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi di utilizzo:
  %(prog)s -i /path/to/p7m/files
  %(prog)s --input ./documenti_firmati
  
Struttura output:
  output_directory/
  └── YYYYMMDD_HHMMSS/
      ├── pdf/
      │   └── documento.pdf
      └── signed/
          └── documento_signature_info.txt
        """
    )
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Directory contenente i file p7m da processare'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='./output',
        help='Directory di output (default: ./output)'
    )
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("P7M EXTRACTOR - Estrazione PDF e Firme Digitali")
    print("=" * 80)
    print()
    
    process_directory(args.input, args.output)


if __name__ == "__main__":
    main()
