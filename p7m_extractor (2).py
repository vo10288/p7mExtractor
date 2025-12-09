#!/usr/bin/env python3
"""
P7M Extractor - Estrae PDF e firme digitali da file p7m (PKCS#7 e CAdES)
Versione con estrazione raw per file CAdES problematici
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


def extract_pdf_raw(p7m_data):
    """
    Estrae il PDF cercando i marker %PDF e %%EOF nei byte raw
    
    Args:
        p7m_data: bytes del file p7m
        
    Returns:
        bytes del PDF o None
    """
    try:
        # Cerca l'header del PDF
        pdf_start = p7m_data.find(b'%PDF')
        if pdf_start == -1:
            return None
        
        # Cerca la fine del PDF
        pdf_end = p7m_data.rfind(b'%%EOF')
        if pdf_end == -1:
            return None
        
        # Estrai il PDF (includi %%EOF)
        pdf_end += 5  # Lunghezza di "%%EOF"
        pdf_content = p7m_data[pdf_start:pdf_end]
        
        # Verifica che sia effettivamente un PDF valido
        if len(pdf_content) > 100 and pdf_content[:4] == b'%PDF':
            return pdf_content
        
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


def find_original_pdf(p7m_path):
    """
    Cerca il PDF originale associato al file p7m (per firme detached)
    
    Args:
        p7m_path: Path del file p7m
        
    Returns:
        Path del PDF se trovato, altrimenti None
    """
    # Rimuovi .p7m dall'estensione
    pdf_path = Path(str(p7m_path)[:-4])
    
    if pdf_path.exists() and pdf_path.is_file():
        return pdf_path
    
    # Prova anche senza l'estensione .pdf se è già inclusa
    base_name = p7m_path.stem
    if base_name.endswith('.pdf'):
        pdf_path = p7m_path.parent / base_name
        if pdf_path.exists() and pdf_path.is_file():
            return pdf_path
    
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
        
        # Determina il tipo di firma
        is_cades = False
        is_detached = False
        is_raw_extraction = False
        signed_data = None
        pdf_content = None
        
        if content_type == 'signed_data':
            signed_data = content_info['content']
        elif content_type == '1.2.840.113549.1.9.16.1.31':  # CAdES
            is_cades = True
            signed_data = content_info['content']
        else:
            return False, None, None, f"Tipo di contenuto non supportato: {content_type}"
        
        # METODO 1: Prova estrazione standard dalla struttura ASN.1
        if signed_data and 'encap_content_info' in signed_data:
            pdf_content = extract_content_from_signed_data(signed_data)
        
        # METODO 2: Se non trovato, prova estrazione RAW
        if pdf_content is None:
            pdf_content = extract_pdf_raw(p7m_data)
            if pdf_content:
                is_raw_extraction = True
        
        # METODO 3: Se ancora non trovato, cerca file PDF separato (firma detached)
        original_pdf_path = None
        if pdf_content is None:
            is_detached = True
            original_pdf_path = find_original_pdf(p7m_file_path)
            
            if original_pdf_path:
                with open(original_pdf_path, 'rb') as f:
                    pdf_content = f.read()
        
        if pdf_content is None:
            return False, None, None, (
                "Impossibile estrarre il PDF. "
                "Il file potrebbe essere corrotto o usare un formato non supportato."
            )
        
        # Verifica che sia effettivamente un PDF
        if not pdf_content.startswith(b'%PDF'):
            return False, None, None, "Il contenuto estratto non è un PDF valido"
        
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
        pdf_output_path = pdf_dir / f"{original_filename}"
        if not pdf_output_path.suffix:
            pdf_output_path = pdf_dir / f"{original_filename}.pdf"
        
        with open(pdf_output_path, 'wb') as f:
            f.write(pdf_content)
        
        # Estrai informazioni sulla firma
        signature_info = []
        signature_info.append(f"File P7M: {p7m_file_path}\n")
        if original_pdf_path:
            signature_info.append(f"File PDF originale: {original_pdf_path}\n")
        signature_info.append(f"Data estrazione: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Determina il tipo di firma e metodo di estrazione
        if is_cades:
            if is_raw_extraction:
                firma_tipo = "CAdES (PDF estratto da struttura raw)"
            elif is_detached:
                firma_tipo = "CAdES Detached (firma separata dal documento)"
            else:
                firma_tipo = "CAdES Embedded (firma incorporata)"
        else:
            if is_detached:
                firma_tipo = "PKCS#7 Detached (firma separata)"
            else:
                firma_tipo = "PKCS#7 Embedded (firma incorporata)"
        
        signature_info.append(f"Tipo firma: {firma_tipo}\n")
        signature_info.append(f"Dimensione PDF: {len(pdf_content)} bytes ({len(pdf_content)/1024:.2f} KB)\n")
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
                    
                    # Estrai informazioni dal subject
                    subject_dict = {}
                    for attr in cert.subject:
                        subject_dict[attr.oid._name] = attr.value
                    
                    if 'commonName' in subject_dict:
                        signature_info.append(f"Firmatario: {subject_dict['commonName']}\n")
                    if 'organizationName' in subject_dict:
                        signature_info.append(f"Organizzazione: {subject_dict['organizationName']}\n")
                    if 'countryName' in subject_dict:
                        signature_info.append(f"Paese: {subject_dict['countryName']}\n")
                    if 'serialNumber' in subject_dict:
                        signature_info.append(f"Codice Fiscale/P.IVA: {subject_dict['serialNumber']}\n")
                    
                    signature_info.append(f"\nSubject completo: {cert.subject.rfc4514_string()}\n")
                    signature_info.append(f"Issuer: {cert.issuer.rfc4514_string()}\n")
                    signature_info.append(f"Serial Number Certificato: {cert.serial_number}\n")
                    signature_info.append(f"Valido da: {cert.not_valid_before_utc}\n")
                    signature_info.append(f"Valido fino a: {cert.not_valid_after_utc}\n")
                    
                    # Verifica validità
                    now = datetime.now(cert.not_valid_before_utc.tzinfo)
                    if now < cert.not_valid_before_utc:
                        signature_info.append("⚠️  STATO: Non ancora valido\n")
                    elif now > cert.not_valid_after_utc:
                        signature_info.append("⚠️  STATO: SCADUTO\n")
                    else:
                        signature_info.append("✓ STATO: Valido\n")
                    
                    signature_info.append(f"Algoritmo firma certificato: {cert.signature_algorithm_oid._name}\n")
                    signature_info.append("\n")
        except Exception as e:
            signature_info.append(f"⚠️  Impossibile estrarre informazioni certificati: {str(e)}\n\n")
        
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
                
                # Cerca timestamp
                has_timestamp = False
                if 'unsigned_attrs' in signer_info and signer_info['unsigned_attrs']:
                    for attr in signer_info['unsigned_attrs']:
                        attr_type = attr['type'].native
                        if attr_type == '1.2.840.113549.1.9.16.2.14':  # signature-time-stamp
                            has_timestamp = True
                            signature_info.append("Timestamp: Presente\n")
                            break
                
                if not has_timestamp:
                    signature_info.append("Timestamp: Non presente\n")
                
                signature_info.append("\n")
        except Exception as e:
            signature_info.append(f"⚠️  Impossibile estrarre informazioni firmatari: {str(e)}\n\n")
        
        # Salva le informazioni sulla firma
        signature_output_path = signed_dir / f"{Path(original_filename).stem}_signature_info.txt"
        with open(signature_output_path, 'w', encoding='utf-8') as f:
            f.writelines(signature_info)
        
        return True, pdf_output_path, signature_output_path, None
        
    except Exception as e:
        import traceback
        error_detail = f"Errore: {str(e)}\n{traceback.format_exc()}"
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
        print(f"🔄 Processando: {p7m_file.name}...", end=" ", flush=True)
        
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
        print(f"\n⚠️  Dettaglio errori:")
        for err in errors_detail:
            print(err)
    
    if success_count > 0:
        print(f"\n📂 File estratti salvati in: {output_path}")
        print(f"\nStruttura creata:")
        print(f"  {output_path}/")
        print(f"  └── YYYYMMDD_HHMMSS/")
        print(f"      ├── pdf/          (file PDF estratti)")
        print(f"      └── signed/       (informazioni firme)")


def main():
    parser = argparse.ArgumentParser(
        description="Estrae PDF e informazioni sulle firme digitali da file p7m (PKCS#7 e CAdES)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi di utilizzo:
  %(prog)s -i /path/to/p7m/files
  %(prog)s --input ./documenti_firmati -o ./output_custom
  
Formati supportati:
  - PKCS#7 signed-data (embedded)
  - PKCS#7 detached signature
  - CAdES-BES (embedded e raw)
  - CAdES-BES (detached)
  
Metodi di estrazione:
  1. Estrazione standard dalla struttura ASN.1
  2. Estrazione raw cercando marker %PDF e %%EOF
  3. Ricerca file PDF separato (per firme detached)
  
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
    print("Supporto: PKCS#7, CAdES (embedded, raw, detached)")
    print("=" * 80)
    print()
    
    process_directory(args.input, args.output)


if __name__ == "__main__":
    main()
