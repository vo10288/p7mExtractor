#!/usr/bin/env python3
"""
Script di test per verificare l'installazione delle dipendenze
"""

import sys

def check_dependencies():
    """Verifica che tutte le dipendenze siano installate"""
    
    print("Verifica dipendenze per P7M Extractor...")
    print("=" * 60)
    
    all_ok = True
    
    # Check Python version
    print(f"\n✓ Python version: {sys.version}")
    if sys.version_info < (3, 7):
        print("❌ ERRORE: Python 3.7 o superiore richiesto")
        all_ok = False
    
    # Check cryptography
    try:
        import cryptography
        print(f"✓ cryptography: {cryptography.__version__}")
    except ImportError:
        print("❌ cryptography NON installato")
        print("   Installa con: pip install cryptography")
        all_ok = False
    
    # Check asn1crypto
    try:
        import asn1crypto
        print(f"✓ asn1crypto: {asn1crypto.__version__}")
    except ImportError:
        print("❌ asn1crypto NON installato")
        print("   Installa con: pip install asn1crypto")
        all_ok = False
    
    # Check specific modules
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        from asn1crypto import cms
        print("✓ Tutti i moduli necessari sono disponibili")
    except ImportError as e:
        print(f"❌ Errore nell'importazione dei moduli: {e}")
        all_ok = False
    
    print("\n" + "=" * 60)
    
    if all_ok:
        print("✅ Tutti i requisiti sono soddisfatti!")
        print("\nPuoi usare il programma con:")
        print("  python p7m_extractor.py -i <directory_input>")
        return 0
    else:
        print("❌ Alcuni requisiti non sono soddisfatti")
        print("\nInstalla le dipendenze mancanti con:")
        print("  pip install -r requirements.txt")
        return 1

if __name__ == "__main__":
    sys.exit(check_dependencies())
