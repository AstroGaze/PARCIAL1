import Crypto.Random
import Crypto.Util.number
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PyPDF2 import PdfReader, PdfWriter, PageObject

# Configuración de parámetros
tamano_bits = 1024
exponente_publico = 65537

# Generación de claves para Alice
primo_alice_1 = Crypto.Util.number.getPrime(tamano_bits, randfunc=Crypto.Random.get_random_bytes)
primo_alice_2 = Crypto.Util.number.getPrime(tamano_bits, randfunc=Crypto.Random.get_random_bytes)
n_alice = primo_alice_1 * primo_alice_2
phi_alice = (primo_alice_1 - 1) * (primo_alice_2 - 1)
d_alice = Crypto.Util.number.inverse(exponente_publico, phi_alice)

# Generación de claves para la Autoridad Certificadora (AC)
primo_ac_1 = Crypto.Util.number.getPrime(tamano_bits, randfunc=Crypto.Random.get_random_bytes)
primo_ac_2 = Crypto.Util.number.getPrime(tamano_bits, randfunc=Crypto.Random.get_random_bytes)
n_ac = primo_ac_1 * primo_ac_2
phi_ac = (primo_ac_1 - 1) * (primo_ac_2 - 1)
d_ac = Crypto.Util.number.inverse(exponente_publico, phi_ac)

# Lectura y hash del PDF
ruta_pdf = "NDA.pdf"
lector_pdf = PdfReader(ruta_pdf)
pagina_pdf = lector_pdf.pages[0]
texto_pdf = pagina_pdf.extract_text()
hash_texto_pdf = hashlib.sha256(texto_pdf.encode()).hexdigest()
print("PDF hasheado: ", hash_texto_pdf, "\n")

# Firma por parte de Alice
hash_int = int.from_bytes(hash_texto_pdf.encode(), 'big')
firma_alice = pow(hash_int, d_alice, n_alice)
print("Firma de Alice:", firma_alice, "\n")

# Verificación y firma por parte de la AC
firma_descifrada_alice = pow(firma_alice, exponente_publico, n_alice)
print("AC verifica la firma de Alice:", firma_descifrada_alice, "\n")

firma_ac = pow(firma_descifrada_alice, d_ac, n_ac)
print("Firma de la AC:", firma_ac, "\n")

# Verificación por parte de Bob
firma_descifrada_ac = pow(firma_ac, exponente_publico, n_ac)
print("Bob verifica la firma de la AC:", firma_descifrada_ac, "\n")
