from scitokens.scitokens import SciToken
import time as t
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import matplotlib.pyplot as plot

def create_key_list():
   private_key = rsa.generate_private_key(
         public_exponent=65537,
         key_size=2048,
         backend=default_backend()
   )
   return private_key

@staticmethod
def sign_token_benchmark(private_key, scope):
   output = []
   serialized_token_list = []
   token = SciToken(key=private_key, algorithm="RS256")
   token.update_claims({"scope": scope})
   starttime = t.time()
   for i in range(0, 10000):
      serialized_token = token.serialize(issuer="https://demo.scitokens.org")
      serialized_token_list.append(serialized_token)
   endtime = t.time()
   output.append(serialized_token_list)
   output.append(endtime - starttime)
   return output

def verify_token_benchmark(serialized_token_list, private_key):
   public_key = private_key.public_key()
   pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
   starttime = t.time()
   for i in range(0, 10000):
      SciToken.deserialize(serialized_token_list[i], public_key=pem)
   endtime = t.time()
   return endtime - starttime

def main():
   scope = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
   for i in range(0, 10):
      scope += scope
   sign_time = []
   verify_time = []
   token_size = [571, 107067, 213563, 320059]
   
   private_key = create_key_list()
   result = sign_token_benchmark(private_key, "")
   sign_time.append(result[1])
   verify_time.append(verify_token_benchmark(result[0], private_key))

   private_key = create_key_list()
   result = sign_token_benchmark(private_key, scope)
   sign_time.append(result[1])
   verify_time.append(verify_token_benchmark(result[0], private_key))

   private_key = create_key_list()
   result = sign_token_benchmark(private_key, scope + scope)
   sign_time.append(result[1])
   verify_time.append(verify_token_benchmark(result[0], private_key))

   private_key = create_key_list()
   result = sign_token_benchmark(private_key, scope + scope + scope)
   sign_time.append(result[1])
   verify_time.append(verify_token_benchmark(result[0], private_key))

   plot.title("RS Benchmark")
   plot.plot(token_size, sign_time, label='Sign Time')
   plot.plot(token_size, verify_time, label='Verify Time')
   plot.xlabel("Token Size")
   plot.ylabel("Time")
   plot.legend(loc='upper left')
   for i, j in zip(token_size, sign_time):
      plot.annotate(str("{:.6f}".format(j)), xy=(i, j))
   for i, j in zip(token_size, verify_time):
      plot.annotate(str("{:.6f}".format(j)), xy=(i, j))
   plot.savefig('rs_benchmark.jpg')
   plot.show()
   
if __name__=="__main__":
   main()