
import hashlib
import random

# Примечание: str преобразуется как есть, str([1,2,3,4]) преобразуется в "[1,2,3,4]"
def H(*args) -> int:
    """Односторонняя хэш-функция."""
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha256(a.encode("utf-8")).hexdigest(), 16)

def cryptrand(n: int = 1024):
    return random.SystemRandom().getrandbits(n) % N

# Большое безопасное простое число (N = 2q+1, где q - простое число)
# Вся арифметика выполняется по модулю N
# (сгенерирован с использованием "openssl dhparam -текст 1024")
N = """00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
       4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
       c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
       97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
       c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
       c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
       16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
       9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:
       d0:d4:ca:3c:50:0b:88:5f:e3"""
N = int("".join(N.split()).replace(":", ""), 16)
g = 2  # Генератор по модулю N

k = H(N, g) # Параметр множителя (k=3 в SRP-6)

F = '#0x'   # Спецификатор формата
print("#. H, N, g, и k заранее известны как клиенту, так и серверу:")
print(f'{H = }\n{N = :{F}}\n{g = :{F}}\n{k = :{F}}')

print("\n0. сервер хранит (I, s, v) в своей базе данных паролей")

# Сервер должен сначала сгенерировать средство проверки пароля
I = "person"        # Username
p = "password1234"  # Password
s = cryptrand(64)   # Salt for the user
x = H(s, I, p)      # Private key
v = pow(g, x, N)    # Password verifier

print(f'{I = }\n{p = }\n{s = :{F}}\n{x = :{F}}\n{v = :{F}}')


print("\n1. клиент отправляет имя пользователя I и общедоступное эфемерное значение A на сервер")
a = cryptrand()
A = pow(g, a, N)
print(f"{I = }\n{A = :{F}}")  # client->server (I, A)



print("\n2. сервер отправляет соли пользователя и общедоступное эфемерное значение B клиенту")
b = cryptrand()
B = (k * v + pow(g, b, N)) % N
print(f"{s = :{F}}\n{B = :{F}}")  # server->client (s, B)



print("\n3. клиент и сервер вычисляют параметр случайного скремблирования")
u = H(A, B)  # Random scrambling parameter
print(f"{u = :{F}}")



print("\n4.клиент вычисляет ключ сеанса")
x = H(s, I, p)
S_c = pow(B - k * pow(g, x, N), a + u * x, N)
K_c = H(S_c)
print(f"{S_c = :{F}}\n{K_c = :{F}}")



print("\n5. сервер вычисляет ключ сеанса")
S_s = pow(A * pow(v, u, N), b, N)
K_s = H(S_s)
print(f"{S_s = :{F}}\n{K_s = :{F}}")



print("\n6. клиент отправляет подтверждение сеансового ключа на сервер")
M_c = H(H(N) ^ H(g), H(I), s, A, B, K_c)
print(f"{M_c = :{F}}")
# клиент->сервер (M_c) ; сервер проверяет M_c



print("\n7. сервер отправляет подтверждение сеансового ключа клиенту")
M_s = H(A, M_c, K_s)
print(f"{M_s = :{F}}")
# сервер->клиент (M_s) ; клиент проверяет M_s

