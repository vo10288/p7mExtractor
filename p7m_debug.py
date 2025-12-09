#!/usr/bin/env python3
"""
P7M Debug Tool - Analizza la struttura interna dei file p7m
"""

import argparse
import sys
from pathlib import Path
from asn1crypto import cms, core
import binascii


def analyze_p7m_structure(p7m_path, verbose=False):
    """
    Analizza e mostra la struttura completa di un file p7m
    """
    print(f"\n{'='*80}")
    print(f"ANALISI FILE: {p7m_path}")
    print(f"{'='*80}\n")
    
    try:
        with open(p7m_path, 'rb') as f:
            p7m_data = f.read()
        
        print(f"📊 Dimensione file: {len(p7m_data)} bytes ({len(p7m_data)/1024:.2f} KB)\n")
        
        # Parse del ContentInfo principale
        content_info = cms.ContentInfo.load(p7m_data)
        content_type = content_info['content_type'].native
        
        print(f"📦 Content Type: {content_type}")
        print(f"   OID: {content_info['content_type'].dotted}\n")
        
        # Analizza il contenuto
        content = content_info['content']
        
        print("🔍 STRUTTURA DEL CONTENUTO:")
        print(f"   Tipo oggetto: {type(content).__name__}")
        
        # Mostra tutti i campi disponibili
        if hasattr(content, '_fields'):
            print(f"\n   Campi disponibili:")
            for field_name in content._fields:
                try:
                    field_value = content[field_name]
                    if field_value is not None:
                        print(f"     ✓ {field_name}: {type(field_value).__name__}")
                        
                        # Mostra dettagli per campi specifici
                        if field_name == 'encap_content_info' and verbose:
                            print(f"       └─ Analisi dettagliata:")
                            encap_info = field_value
                            if 'content_type' in encap_info:
                                print(f"          content_type: {encap_info['content_type'].native}")
                            if 'content' in encap_info:
                                enc_content = encap_info['content']
                                if enc_content:
                                    print(f"          content presente: Sì ({len(enc_content.native) if hasattr(enc_content, 'native') else 'N/A'} bytes)")
                                else:
                                    print(f"          content presente: No (None)")
                        
                        if field_name == 'content' and hasattr(field_value, 'native'):
                            content_bytes = field_value.native
                            if content_bytes:
                                print(f"       └─ Dimensione: {len(content_bytes)} bytes")
                                # Verifica se è un PDF
                                if content_bytes[:4] == b'%PDF':
                                    print(f"       └─ ✅ CONTIENE UN PDF!")
                                elif b'%PDF' in content_bytes[:1000]:
                                    print(f"       └─ ✅ Possibile PDF (header trovato nei primi 1000 bytes)")
                    else:
                        print(f"       {field_name}: None")
                except Exception as e:
                    print(f"       {field_name}: Errore lettura ({str(e)[:50]})")
        
        # Cerca ricorsivamente contenuti nested
        print(f"\n🔎 RICERCA CONTENUTO PDF NESTED:")
        pdf_found = search_for_pdf(content, level=1)
        
        if not pdf_found:
            print("   ❌ Nessun PDF trovato nella struttura")
            
            # Prova un'analisi raw
            print(f"\n🔬 ANALISI RAW DEL FILE:")
            if b'%PDF' in p7m_data:
                pdf_start = p7m_data.find(b'%PDF')
                print(f"   ✅ Header PDF trovato alla posizione {pdf_start}")
                print(f"   Primi 100 bytes dal PDF:")
                print(f"   {p7m_data[pdf_start:pdf_start+100]}")
                
                # Cerca EOF
                if b'%%EOF' in p7m_data:
                    pdf_end = p7m_data.rfind(b'%%EOF') + 5
                    print(f"   ✅ Fine PDF trovata alla posizione {pdf_end}")
                    pdf_content = p7m_data[pdf_start:pdf_end]
                    print(f"   📄 Dimensione PDF estratto: {len(pdf_content)} bytes")
                    
                    # Salva il PDF estratto
                    output_path = Path(p7m_path).parent / f"_DEBUG_{Path(p7m_path).stem}_extracted.pdf"
                    with open(output_path, 'wb') as f:
                        f.write(pdf_content)
                    print(f"   💾 PDF salvato in: {output_path}")
                    return True
            else:
                print(f"   ❌ Header PDF non trovato nel file raw")
        
        return pdf_found
        
    except Exception as e:
        print(f"❌ ERRORE: {str(e)}")
        import traceback
        if verbose:
            traceback.print_exc()
        return False


def search_for_pdf(obj, level=0, max_level=10):
    """
    Cerca ricorsivamente contenuto PDF nella struttura ASN.1
    """
    if level > max_level:
        return False
    
    indent = "   " * level
    
    try:
        # Se è un oggetto con native, controlla se è un PDF
        if hasattr(obj, 'native'):
            native_data = obj.native
            if isinstance(native_data, bytes) and len(native_data) > 4:
                if native_data[:4] == b'%PDF':
                    print(f"{indent}✅ PDF TROVATO! (livello {level}, {len(native_data)} bytes)")
                    return True
        
        # Se è un ContentInfo, analizza il contenuto
        if hasattr(obj, '__class__') and obj.__class__.__name__ == 'ContentInfo':
            print(f"{indent}→ ContentInfo trovato (livello {level})")
            if 'content' in obj:
                return search_for_pdf(obj['content'], level + 1, max_level)
        
        # Se è un dizionario o ha campi, esploraìli
        if hasattr(obj, '_fields'):
            for field_name in obj._fields:
                try:
                    field_value = obj[field_name]
                    if field_value is not None:
                        if search_for_pdf(field_value, level + 1, max_level):
                            return True
                except:
                    pass
        
        # Se è una sequenza, esplora gli elementi
        if hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            try:
                for item in obj:
                    if search_for_pdf(item, level + 1, max_level):
                        return True
            except:
                pass
                
    except Exception as e:
        pass
    
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Analizza la struttura interna di file p7m per debug"
    )
    
    parser.add_argument(
        'file',
        help='File .p7m da analizzare'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Output verboso con dettagli completi'
    )
    
    args = parser.parse_args()
    
    file_path = Path(args.file)
    
    if not file_path.exists():
        print(f"❌ File non trovato: {args.file}")
        return 1
    
    print("=" * 80)
    print("P7M DEBUG TOOL - Analisi struttura file")
    print("=" * 80)
    
    success = analyze_p7m_structure(file_path, args.verbose)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
