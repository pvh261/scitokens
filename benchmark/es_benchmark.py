from scitokens.scitokens import SciToken
import time as t
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import sys
import matplotlib.pyplot as plot

def create_key_list():
   private_key_list = []
   for i in range(0, 10000):
      private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()
      )
      private_key_list.append(private_key)
   return private_key_list

def sign_token_benchmark(private_key_list, scope):
   result = []
   serialized_token_list = []
   key_id = "id"
   token = SciToken(key=private_key_list[0], algorithm="ES256", key_id=key_id)
   token.update_claims({"scope": scope})
   starttime = t.time()
   for i in range(0, 10000):
      serialized_token = token.serialize(issuer="https://demo.scitokens.org")
      serialized_token_list.append(serialized_token)
   endtime = t.time()
   result.append(serialized_token_list)
   result.append(endtime-starttime)
   return result

def verify_token_benchmark(serialized_token_list, private_key_list):
   public_key = private_key_list[0].public_key()
   pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
   starttime = t.time()
   for i in range(0, 10000):
      SciToken.deserialize(serialized_token_list[0], public_key=pem)
   endtime = t.time()
   return endtime - starttime

def main():
   scope = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
   for i in range(0, 10):
      scope += scope
   sign_time = []
   verify_time = []
   token_size = [331, 435, 539, 643]

   private_key_list = create_key_list()
   result = sign_token_benchmark(private_key_list, "")
   sign_time.append(result[1])
   verify_time.append(verify_token_benchmark(result[0], private_key_list))

   private_key_list = create_key_list()
   result = sign_token_benchmark(private_key_list, scope)
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

   plot.title("ES Benchmark")
   plot.plot(token_size, sign_time, label='Sign Time')
   plot.plot(token_size, verify_time, label='Verify Time')
   plot.xlabel("Token Size")
   plot.ylabel("Time")
   plot.legend(loc='upper right')
   for i, j in zip(token_size, sign_time):
      plot.annotate(str("{:.6f}".format(j)), xy=(i, j))
   for i, j in zip(token_size, verify_time):
      plot.annotate(str("{:.6f}".format(j)), xy=(i, j))
   plot.savefig('es_benchmark.jpg')
   plot.show()
   
if __name__=="__main__":
   main()