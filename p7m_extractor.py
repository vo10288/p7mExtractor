#!/usr/bin/env python3
"""
P7M Extractor - Estrae PDF e firme digitali da file p7m (PKCS#7 e CAdES)
"""

import argparse
import os
import sys
from pathlib import Path
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from asn1crypto import cms, core
import shutil


def extract_signed_data_from_cades(content_info):
    """
    Estrae signed_data da un file in formato CAdES (timestamped-data)
    
    Args:
        content_info: ContentInfo object
        
    Returns:
        SignedData object o None
    """
    try:
        # Per CAdES, proviamo diverse strategie di estrazione
        timestamped_data = content_info['content']
        
        # Strategia 1: cerca encap_content_info
        if hasattr(timestamped_data, 'chosen') and timestamped_data.chosen:
            inner_data = timestamped_data.chosen
            if 'content' in inner_data and inner_data['content']:
                try:
                    inner_content_info = cms.ContentInfo.load(inner_data['content'].native)
                    if inner_content_info['content_type'].native == 'signed_data':
                        return inner_content_info['content']
                except:
                    pass
        
        # Strategia 2: il timestamped-data potrebbe contenere direttamente signed data
        if 'encap_content_info' in timestamped_data:
            return timestamped_data
            
        return None
    except Exception as e:
        return None


def extract_content_from_signed_data(signed_data):
    """
    Estrae il contenuto (PDF) da un oggetto SignedData
    
    Args:
        signed_data: SignedData object
        
    Returns:
        bytes del contenuto o None
    """
    try:
        encap_content_info = signed_data['encap_content_info']
        pdf_content = encap_content_info['content']
        
        if pdf_content is None:
            return None
            
        # A volte il contenuto è wrapped
        if hasattr(pdf_content, 'native'):
            return pdf_content.native
        else:
            return bytes(pdf_content)
            
    except Exception as e:
        return None


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
        content_type = content_info['content_type'].native
        
        signed_data = None
        is_cades = False
        
        # Gestisci diversi tipi di contenuto
        if content_type == 'signed_data':
            signed_data = content_info['content']
        elif content_type == '1.2.840.113549.1.9.16.1.31':  # timestamped_data (CAdES)
            is_cades = True
            signed_data = extract_signed_data_from_cades(content_info)
            if signed_data is None:
                # Fallback: tratta il timestamped_data come signed_data
                signed_data = content_info['content']
        else:
            return False, None, None, f"Tipo di contenuto non supportato: {content_type}"
        
        # Estrai il contenuto (PDF)
        pdf_content = extract_content_from_signed_data(signed_data)
        
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
        signature_info.append(f"Formato: {'CAdES (timestamped-data)' if is_cades else 'PKCS#7 (signed-data)'}\n")
        signature_info.append("=" * 80 + "\n\n")
        
        # Informazioni sui certificati
        try:
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
                    
                    # Estrai informazioni aggiuntive dal subject
                    try:
                        for attr in cert.subject:
                            if attr.oid._name == 'commonName':
                                signature_info.append(f"Nome Comune: {attr.value}\n")
                            elif attr.oid._name == 'organizationName':
                                signature_info.append(f"Organizzazione: {attr.value}\n")
                            elif attr.oid._name == 'countryName':
                                signature_info.append(f"Paese: {attr.value}\n")
                    except:
                        pass
                    
                    signature_info.append(f"Algoritmo firma: {cert.signature_algorithm_oid._name}\n")
                    signature_info.append("\n")
        except Exception as e:
            signature_info.append(f"Informazioni certificati non disponibili: {str(e)}\n\n")
        
        # Informazioni sui firmatari
        try:
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
                
                # Timestamp se disponibile
                if 'unsigned_attrs' in signer_info and signer_info['unsigned_attrs']:
                    for attr in signer_info['unsigned_attrs']:
                        if attr['type'].native == '1.2.840.113549.1.9.16.2.14':  # signature-time-stamp
                            signature_info.append("Timestamp presente: Sì\n")
                            break
                
                signature_info.append("\n")
        except Exception as e:
            signature_info.append(f"Informazioni firmatari non disponibili: {str(e)}\n\n")
        
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
    errors_detail = []
    
    for p7m_file in p7m_files:
        print(f"🔄 Processando: {p7m_file.name}...", end=" ")
        
        success, pdf_path, sig_path, error = extract_p7m(p7m_file, output_path)
        
        if success:
            print("✅")
            success_count += 1
        else:
            print(f"❌")
            error_count += 1
            errors_detail.append(f"  - {p7m_file.name}: {error}")
    
    print(f"\n{'='*80}")
    print(f"✅ Processati con successo: {success_count}")
    print(f"❌ Errori: {error_count}")
    
    if errors_detail:
        print(f"\nDettaglio errori:")
        for err in errors_detail:
            print(err)
    
    print(f"\n📂 File estratti salvati in: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Estrae PDF e informazioni sulle firme digitali da file p7m (PKCS#7 e CAdES)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi di utilizzo:
  %(prog)s -i /path/to/p7m/files
  %(prog)s --input ./documenti_firmati -o ./output_custom
  
Formati supportati:
  - PKCS#7 signed-data
  - CAdES (timestamped-data)
  
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
    print("P7M EXTRACTOR - Estrazione PDF e Firme Digitali (PKCS#7 e CAdES)")
    print("=" * 80)
    print()
    
    process_directory(args.input, args.output)


if __name__ == "__main__":
    main()
