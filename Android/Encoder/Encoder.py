import codecs
import base64
class Encoder(object):
    def encoder(self, param):
        encoded_param = base64.b64encode(b'param')

        return encoded_param

    def decoder(self, param):
        decoded_param = param.decode()
        return decoded_param

enc=Encoder()
print(enc.encoder('welcome'))
