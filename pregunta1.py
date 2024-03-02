import Crypto.Util.number
import Crypto.Random
import hashlib

# Generar un mensaje de 1050 caracteres
msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin ornare in nisl eu vehicula. Mauris a orci velit, quis lacinia lectus. Cras sed libero velit, sit amet luctus dolor tincidunt. Maecenas eget tristique elit. In hac habitasse platea dictumst. Fusce ultricies risus vel lectus varius, eget ultrices sapien ultrices. Fusce velit mauris, aliquet id nisl et, sodales tincidunt odio. Nunc et orci quis eros laoreet hendrerit. Sed eget tellus velit. Praesent sed risus sed tellus lacinia molestie. Nunc eget ultrices purus. Quisque eleifend neque id felis mollis, at tincidunt sapien convallis. Nunc ultricies lacus velit, eget malesuada turpis pulvinar eu. Fusce vehicula lectus non erat convallis, sit amet sodales eros hendrerit. Nunc euismod odio ut elit posuere, sed luctus eros aliquet. Sed aliquam, augue at tristique ultricies, magna felis sodales magna, vel laoreet arcu purus eu enim. Maecenas sit amet ligula sit amet felis sodales venenatis. Duis ac nisi in felis vehicula tincidunt. Nullam mattis ultrices orci, ut consequat erat elementum eu. Sed vel erat ac justo ullamcorper sollicitudin. Nunc sed neque et massa viverra aliquam. Nullam euismod purus ac massa placerat, et luctus mauris ornare. Fusce a magna ac tortor pulvinar ultrices. Duis sed lacus eget magna vestibulum ullamcorper. Nunc tempor, odio sit amet facilisis tincidunt, quam augue congue urna, ac sodales libero sapien ut nibh. Nunc eget orci vel velit aliquam consectetur. Nam eget tellus ac lectus ultricies tristique. Donec et elit quis eros ultricies tincidunt. Fusce nec neque ut quam egestas viverra. Donec vitae lacus ac neque aliquam ornare. Sed eget augue in velit hendrerit hendrerit. Sed eget elit a sapien tincidunt eleifend. Nunc tincidunt turpis at purus gravida, vitae aliquam sem ultrices."

# Hash del mensaje original (h(M))
hash_original = hashlib.sha256(msg.encode('utf-8')).hexdigest()

# Número de bits para los primos, aumentado a 2048 para manejar el tamaño del mensaje
bits = 2048

# Obtener los primos para Bob (ya que Alice enviará el mensaje a Bob)
pB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
nB = pB * qB
phiB = (pB - 1) * (qB - 1)
e = 65537
dB = Crypto.Util.number.inverse(e, phiB)

# Dividir el mensaje en partes de 128 caracteres y cifrar
partes_msg = [msg[i:i+128] for i in range(0, len(msg), 128)]
cifrado_parts = []

for parte in partes_msg:
    m = int.from_bytes(parte.encode('utf-8'), byteorder='big')
    if m < nB:
        c = pow(m, e, nB)
        cifrado_parts.append(c)
    else:
        raise ValueError("El mensaje es demasiado grande para cifrarlo con la clave generada.")

# Descifrar cada parte del mensaje
descifrado_parts = []

for c in cifrado_parts:
    des = pow(c, dB, nB)
    # Calcular el tamaño correcto para cada parte del mensaje descifrado
    size = (des.bit_length() + 7) // 8
    parte_descifrada = int.to_bytes(des, size, byteorder='big').decode('utf-8', errors='ignore')
    descifrado_parts.append(parte_descifrada)

# Reconstruir el mensaje descifrado
mensaje_descifrado = ''.join(descifrado_parts).rstrip('\x00')

# Hash del mensaje descifrado (h(M'))
hash_descifrado = hashlib.sha256(mensaje_descifrado.encode('utf-8')).hexdigest()

# Comparar los hash
if hash_original == hash_descifrado:
    print("El mensaje es auténtico.")
else:
    print("El mensaje no es autentico.")
    print("Mensaje original: ", msg)
    print("Mensaje descifrado: ", mensaje_descifrado)

# Mostrar los hash para verificación
print("Hash original: ", hash_original)
print("Hash descifrado: ", hash_descifrado)
