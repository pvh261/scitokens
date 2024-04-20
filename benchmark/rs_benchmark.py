from scitokens.scitokens import SciToken
import time as t
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import sys
import matplotlib.pyplot as plot

def create_key_list():
   private_key_list = []
   for i in range(0, 10000):
      private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
      )
      private_key_list.append(private_key)
   return private_key_list

@staticmethod
def sign_token_benchmark(private_key_list, scope):
   result = []
   serialized_token_list = []
   time = 0
   for i in range(0, 10000):
      key_id = "id" + str(i)
      token = SciToken(key=private_key_list[i], algorithm="RS256", key_id=key_id)
      token.update_claims({"scope": scope})
      starttime = t.time()
      serialized_token = token.serialize(issuer="https://demo.scitokens.org")
      endtime = t.time()
      time += endtime - starttime
      serialized_token_list.append(serialized_token)
   result.append(serialized_token_list)
   result.append(time)
   return result

def verify_token_benchmark(serialized_token_list, private_key_list):
   time = 0
   for i in range(0, 10000):
      public_key = private_key_list[i].public_key()
      pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
      starttime = t.time()
      SciToken.deserialize(serialized_token_list[i], public_key=pem)
      endtime = t.time()
      time += endtime - starttime
   return time

def main():
   scope = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
   
   sign_time = []
   verify_time = []
   token_size = [587, 691, 795, 899]

   private_key_list = create_key_list()
   result = sign_token_benchmark(private_key_list, scope)
   sign_time.append(result[1])
   verify_time.append(verify_token_benchmark(result[0], private_key_list))

   private_key_list = create_key_list()
   result = sign_token_benchmark(private_key_list, "")
   sign_time.append(result[1])
   verify_time.append(verify_token_benchmark(result[0], private_key_list))

   private_key_list = create_key_list()
   result = sign_token_benchmark(private_key_list, scope + scope)
   sign_time.append(result[1])
   verify_time.append(verify_token_benchmark(result[0], private_key_list))

   private_key_list = create_key_list()
   result = sign_token_benchmark(private_key_list, scope + scope + scope)
   sign_time.append(result[1])
   verify_time.append(verify_token_benchmark(result[0], private_key_list))

   plot.title("RS Benchmark")
   plot.plot(token_size, sign_time, label='Sign Time')
   plot.plot(token_size, verify_time, label='Verify Time')
   plot.xlabel("Token Size")
   plot.ylabel("Time")
   plot.legend(loc='upper right')
   for i, j in zip(token_size, sign_time):
      plot.annotate(str("{:.6f}".format(j)), xy=(i, j))
   for i, j in zip(token_size, verify_time):
      plot.annotate(str("{:.6f}".format(j)), xy=(i, j))
   plot.savefig('rs_benchmark.jpg')
   plot.show()
   
if __name__=="__main__":
   main()