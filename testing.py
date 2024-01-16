#Had little incident with those commons and it
#Also this is not a proper way to test if every thing is working
#This only because i had incident with rsa commons
import base64
import json
from commons import RsaCommons
from commons.Utils import Bcolors
from server import ServerFiles

server = RsaCommons.PublicPrivateKeyWrapper.generate(256)

client = RsaCommons.PublicPrivateKeyWrapper.generate(256)


onlyPublicServer = RsaCommons.EncryptOnlyPublic.frombytes(server.exportpublicpem())

onlyPublicClient = RsaCommons.EncryptOnlyPublic.frombytes(client.exportpublicpem())

server_wrapped = RsaCommons.BothSidesWrapped.frombytes(server.exportprivatepem(True), server.exportpublicpem(), onlyPublicClient)
client_wrapped = RsaCommons.BothSidesWrapped.frombytes(client.exportprivatepem(True), client.exportpublicpem(), onlyPublicServer)


data  = b"""
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque consectetur nulla nec laoreet blandit. Sed dapibus nunc id diam convallis, nec facilisis diam ullamcorper. Suspendisse finibus, nunc vel mollis pharetra, enim justo tristique massa, a sodales erat augue id arcu. Fusce at eros eu lorem scelerisque sodales. Integer non felis at ante tincidunt tempus. Fusce gravida mauris in neque mollis euismod ac ut elit. Nullam fringilla arcu nibh, nec faucibus massa mattis eget. Curabitur sed est lacus. Sed mauris arcu, posuere vitae convallis in, imperdiet eu augue.

Pellentesque felis nisl, placerat vitae tristique congue, eleifend vitae nulla. Fusce consectetur risus ut tortor viverra ultricies. Etiam suscipit ex vulputate ante fringilla, ut condimentum quam tincidunt. Donec maximus risus quis magna eleifend auctor. Sed accumsan lacus a turpis dictum, et porttitor enim condimentum. Duis dignissim nisi elementum ex iaculis, eget vehicula lorem elementum. Nulla consectetur accumsan odio ac rutrum. Pellentesque consectetur dapibus fringilla. Cras non finibus magna, ac pulvinar nisl. Duis eget massa eget dui dapibus fermentum. Etiam molestie, dui ac pretium convallis, massa risus egestas diam, a maximus urna risus in dolor. Proin ligula arcu, faucibus non tellus at, congue lobortis arcu. Maecenas aliquam, nisl lacinia efficitur maximus, purus mi tincidunt lectus, quis iaculis sapien velit non massa. Etiam sollicitudin convallis arcu quis pharetra. Donec facilisis sapien eu metus bibendum, at malesuada nunc mollis.

Nunc volutpat condimentum sapien, sed ultrices lorem. Vestibulum laoreet bibendum enim, in dignissim ante rhoncus eu. Nullam ut laoreet nisi, vitae congue lorem. Nunc eget sagittis augue. Morbi vehicula urna in ipsum vulputate malesuada. Suspendisse at sapien risus. Pellentesque maximus dignissim augue, at consectetur neque semper ut. Curabitur et cursus quam, vel porttitor libero.

Ut in quam laoreet, blandit tellus vitae, convallis dui. Sed lacus lacus, tristique vitae egestas non, bibendum vel quam. Pellentesque laoreet nec diam non porttitor. Nunc sagittis risus sed neque venenatis, eget lobortis urna vehicula. Proin molestie libero porttitor, mollis metus a, scelerisque odio. Morbi quis est orci. Vestibulum sed mauris eget leo euismod ultricies. Integer a lacus eget justo elementum vestibulum. Ut posuere, turpis id semper hendrerit, dolor turpis interdum enim, vel blandit ipsum dolor quis dui.

Duis condimentum aliquet magna, ac tempor tellus viverra vel. Vivamus posuere scelerisque ante nec rutrum. Sed vulputate eu elit id tempus. Donec tincidunt fermentum nunc a scelerisque. Sed scelerisque purus quis velit pulvinar aliquet. Aliquam et ex in sapien condimentum maximus. Vivamus orci sem, consectetur vitae erat eu, finibus vehicula eros. Sed a fringilla lectus. Maecenas ultricies sem libero, eu auctor risus varius lobortis. Suspendisse tincidunt nibh id tortor commodo tincidunt. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos."""

encrypted = server_wrapped.encrypt(data)
print(encrypted)

response = client.decrypt(encrypted)

if(response):
    print("error while decrypting")
    raise Exception("ERROR")

decrypted = response.getdata()
print(decrypted)
print(data == decrypted)


MSG = b'ultra krezy mesage'
signature = server_wrapped.sign(MSG)
print(onlyPublicServer.verifysignature(MSG, signature))

converted = base64.b64encode(signature)
print(converted)
back = bytes(base64.b64decode(converted))
print("test:" + str(onlyPublicServer.verifysignature(MSG, signature)))

print(onlyPublicServer.verifysignature(MSG[0:-1], signature))

print(Bcolors.OKGREEN + "OKGREEN" + Bcolors.ENDC)
print(Bcolors.INFO + "INFO" + Bcolors.ENDC)
print(Bcolors.WARNING + "WARNING" + Bcolors.ENDC)
print(Bcolors.SEVERE + "SEVERE" + Bcolors.ENDC)

ServerFiles.HostedFiles.initialize("ftpData", server_wrapped)