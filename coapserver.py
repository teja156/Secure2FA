from coapthon.server.coap import CoAP
from coapthon.resources.resource import Resource
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64decode,b64encode
# from exampleresources import BasicResource

class BasicResource(Resource):
    def __init__(self, name="BasicResource", coap_server=None):
        super(BasicResource, self).__init__(name, coap_server, visible=True,
                                            observable=True, allow_children=True)

        otp = generateOTP()
        print("generated OTP : ",otp)
        self.payload = otp
        # self.payload = "hi"

    def render_GET(self, request):
        otp = generateOTP()
        print("generated OTP : ",otp)
        self.payload = otp
        return self

    def render_PUT(self, request):
        self.payload = request.payload
        return self

    def render_POST(self, request):
        res = BasicResource()
        res.location_query = request.uri_query
        res.payload = request.payload
        return res

    def render_DELETE(self, request):
        return True

class CoAPServer(CoAP):
    def __init__(self, host, port):
        CoAP.__init__(self, (host, port))
        self.add_resource('otp/', BasicResource())

def main():
    server = CoAPServer("127.0.0.1", 1560)
    try:
        server.listen(10)
    except KeyboardInterrupt:
        print "Server Shutdown"
        server.close()
        print "Exiting..."

def generateOTP():
    otp = ""
    for i in range(0,4):
        tmp = random.randint(0,9)
        otp+=str(tmp)
    return otp

def encrypt(otp):
    f = open('rsa.pub')
    key = f.read()
    keyPub = RSA.importKey(key)
    cipher = Cipher_PKCS1_v1_5.new(keyPub)
    cipher_text = cipher.encrypt(otp.encode())
    return b64encode(cipher_text)


if __name__ == '__main__':
    main()

