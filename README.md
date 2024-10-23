practical 1
Aim:Implementing Substitution and Transposition Ciphers

Code:Python code for implementing Caesar Cipher
# A python program to illustrate Caesar Cipher Technique
def encrypt(text, s):
    result = ""
    # traverse text
    for i in range(len(text)):
        char = text[i]
        # Encrypt uppercase characters
        if char.isupper():
            result += chr((ord(char) + s - 65) % 26 + 65)
        # Encrypt lowercase characters
        else:
            result += chr((ord(char) + s - 97) % 26 + 97)

    return result

# Check the above function
text = input("Enter the text to encrypt: ")
s = 3
print("Text: " + text)
str(s)
print("Cipher: " + encrypt(text, s))


Code: Python code for implementing Railfence Cipher
string = input("Enter a string: ")

def RailFence(txt):
    result = ""
    # First loop for even indices
    for i in range(len(string)):
        if i % 2 == 0:
            result += string[i]
    
    # Second loop for odd indices
    for i in range(len(string)):
        if i % 2 != 0:
            result += string[i]
    
    return result

print(RailFence(string))



practical 2
Aim:RSA Encryption and Decryption

Code: Python code for implementing RSA Algorithm

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Generate RSA key pair
keyPair = RSA.generate(1024)
pubKey = keyPair.publickey()

# Display public key
print(f"Public key: (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
print(pubKeyPEM.decode('ascii'))

# Display private key
print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
print(privKeyPEM.decode('ascii'))

# Encryption
msg = 'Ismile Academy'.encode('utf-8')  
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(msg)
print("Encrypted:", binascii.hexlify(encrypted))


Practical 3
Aim: Message Authentication Codes (MAC)

Code: Python code for implementing MD5 Algorithm

import hashlib
result = hashlib.md5(b'Ismile')
result1 = hashlib.md5(b'Esmile')
# printing the equivalent byte value.
print("The byte equivalent of hash is : ", end ="")
print(result.digest())
print("The byte equivalent of hash is : ", end ="")
print(result1.digest())

Code: Python code for implementing SHA Algorithm

import hashlib
str = input("Enter the value to encode: ")
result = hashlib.sha1(str.encode())
print("The hexadecimal equivalent of SHA1 is: ")
print(result.hexdigest())



Practical 4
Aim:Digital Signatures

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random

def generate_signature(private_key, message):
    # Load the private key
    key = RSA.importKey(private_key)
    # Generate SHA-256 hash of the message
    hashed_message = SHA256.new(message.encode('utf-8'))
    # Create a signature using the private key
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(hashed_message)
    return signature

def verify_signature(public_key, message, signature):
    # Load the public key
    key = RSA.importKey(public_key)
    # Generate SHA-256 hash of the message
    hashed_message = SHA256.new(message.encode('utf-8'))
    # Verify the signature using the public key
    verifier = PKCS1_v1_5.new(key)
    return verifier.verify(hashed_message, signature)

# Generate RSA key pair
random_generator = Random.new().read
key_pair = RSA.generate(2048, random_generator)

# Extract public and private keys
public_key = key_pair.publickey().export_key()
private_key = key_pair.export_key()

# Example usage
message = "Hello, World!"
# Generate a digital signature
signature = generate_signature(private_key, message)
print("Generated Signature:", signature)

# Verify the digital signature
is_valid = verify_signature(public_key, message, signature)
print("Signature Verification Result:", is_valid)




Practical 5
Aim:Key Exchange using Diffe-Hellman

from random import randint
if __name__ == '__main__':
    P = 23
    G = 9
    print('The Value of P is : %d' % (P))
    print('The Value of G is : %d' % (G))
    
    a = 4
    print('Secret Number for Alice is : %d' % (a))
    x = int(pow(G, a, P))  
    b = 6
    print('Secret Number for Bob is : %d' % (b))
    y = int(pow(G, b, P))  

    ka = int(pow(y, a, P))  
    kb = int(pow(x, b, P))  
    print('Secret key for Alice is : %d' % (ka))
    print('Secret Key for Bob is : %d' % (kb))


practical 6
Aim:IP Security (IPSec) Configuration

Topology:create topology by taking 3 routers router0,router1,router2 
and take 2 switches switch0 and switch1 and take pc0 and pc1
connect router 0 to router1 and router0 to router1
connect switch0 to router1 and switch1 to router2
connect pc0 to switch0 and pc2 to switch1

configuring pc0: click static enter ipv4 address=192.168.1.2
subnetmask=255.255.255.0 ,default gateway=192.168.1.1

configuration for pc2: enter ipv4 address=192.168.2.2, subnetmask=255.0.0.0
defaultgateway=192.168.2.1
Dns server=0.0.0

configuring router0: click on config to open
interface GigabiEthernet0/1:
ipv4 address 20.0.0.2
subnetmask=255.0.0.0
tx ring limit=10

interface GigabiEthernet0/0:
ipv4 address 30.0.0.2
subnetmask=255.0.0.0
tx ring limit=10


configuring router1: click on config to open
interface GigabiEthernet0/0:
ipv4 address 20.0.0.1
subnetmask=255.0.0.0
tx ring limit=10

configuring router1: click on config to open
interface GigabiEthernet0/1:
ipv4 address 192.168.1.1
subnetmask=255.255.255.255.0
tx ring limit=10


configuring router2: click on config to open
interface GigabiEthernet0/0:
ipv4 address 30.0.0.1
subnetmask=255.0.0.0
tx ring limit=10

configuring router1: click on config to open
interface GigabiEthernet0/1:
ipv4 address 192.168.2.1
subnetmask=255.255.255.255.0
tx ring limit=10

Checking and Enabling the Security features in Router R1 and R2:
Enter the following command in the CLI mode of Router1
Router(config)#ip route 0.0.0.0 0.0.0.0 20.0.0.2
Router(config)#hostname R1
R1(config)#exit
R1#show version

(We see that the security feature is not enabled, hence we need to enable the security package
R1#
R1#configure terminal
Enter configuration commands, one per line. End with CNTL/Z.
R1(config)#
R1(config)#license boot module c1900 technology-package securityk9
R1(config)#exit
R1#
R1#copy run startup-config

R1#reload
R1>enable
R1#show version

(The security package is enabled)

Enter the following command in the CLI mode of Router2
Router(config)#ip route 0.0.0.0 0.0.0.0 30.0.0.2
Router(config)#hostname R2
R2(config)#exit
R2#show version

(We see that the security feature is not enabled, hence we need to enable the security package

R2#
R2#configure terminal
Enter configuration commands, one per line. End with CNTL/Z.
R2(config)#
R2(config)#license boot module c1900 technology-package securityk9
R2(config)#exit
R2#
R2#copy run startup-config
R2#reload
R2>enable
R2#show version

(The security package is enabled)
Enter the following command in the CLI mode of Router0
Router>enable
Router#configure terminal
Router(config)#hostname R0
R0(config)#

Defining the Hostname for all Routers and Configuring the Routers R1 and R2 for IPSec VPN tunnel
R1#configure terminal
R1(config)#access-list 100 permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255
R1(config)#crypto isakmp policy 10
R1(config-isakmp)#encryption aes 256
R1(config-isakmp)#authentication pre-share
R1(config-isakmp)#group 5
R1(config-isakmp)#exit
R1(config)#crypto isakmp key ismile address 30.0.0.1
R1(config)#crypto ipsec transform-set R1->R2 esp-aes 256 esp-sha-hmac
R1(config)#
R2#
R2#configure terminal
R2(config)#access-list 100 permit ip 192.168.2.0 0.0.0.255 192.168.1.0 0.0.0.255
R2(config)#crypto isakmp policy 10
R2(config-isakmp)#encryption aes 256
R2(config-isakmp)#authentication pre-share
R2(config-isakmp)#group 5
R2(config-isakmp)#exit
R2(config)#crypto isakmp key ismile address 20.0.0.1
R2(config)#crypto ipsec transform-set R2->R1 esp-aes 256 esp-sha-hmac
R2(config)#

R1>enable
R1#configure terminal
R1(config)#crypto map IPSEC-MAP 10 ipsec-isakmp
R1(config-crypto-map)#set peer 30.0.0.1
R1(config-crypto-map)#set pfs group5
R1(config-crypto-map)#set security-association lifetime seconds 86400
R1(config-crypto-map)#set transform-set R1->R2

R1(config-crypto-map)#match address 100
R1(config-crypto-map)#exit
R1(config)#interface g0/0
R1(config-if)#crypto map IPSEC-MAP
R2>enable
R2#configure terminal
R2(config)#crypto map IPSEC-MAP 10 ipsec-isakmp
R2(config-crypto-map)#set peer 20.0.0.1
R2(config-crypto-map)#set pfs group5
R2(config-crypto-map)#set security-association lifetime seconds 86400
R2(config-crypto-map)#set transform-set R2->R1
R2(config-crypto-map)#match address 100
R2(config-crypto-map)#exit
R2(config)#interface g0/0
R2(config-if)#crypto map IPSEC-MAP

We verify the working of the IPSec VPN tunnel using the ping command as follows
Output: Pinging PC2(192.168.2.2) from PC1 and then PC1(192.168.1.2) from PC2

Practical 8
Aim:Firewall Configuration and Rule-based Filtering
Part 1: Blocking the HTTP and HTTPS (Port 80 and Port 443) using the Firewall
Before starting with the blocking port process, we note that the applications running at the server-
end are identified with the well-known Port numbers, some of the commonly used are as follows
We perform the blocking Port operation as follows:
Step 1: We access any website through the browser and confirm that the HTTP/HTTPS protocols are
working.
Step 2: We open ‘Windows Defender Firewall’
Next we click on ‘Advanced settings’
Next we click on ‘Inbound Rules’
Then click on ‘New Rule’
Select the radio button ‘Port’ and click ‘Next’ and enter the following
After next, we need to finalise the rule
Click ‘Next’ and we get the following
After clicking the ‘Next’ button we need to name the rule and click finish
The Inbound rule is added
We repeat all the above steps for creating ‘Outbound Rules’, and then try to access the internet.
We see that the accessed is blocked
Part 2: Blocking the website www.android.com
We open the browser and access the website, which is now accessible
We find the IP addresses of the website using the following command
We save the IP addresses
IPv4 216.58.196.68
IPv6 2404:6800:4009:809::2004
We open the windows Firewall settings and apply the Inbound Rule
Insert the IP addresses both IPv4 and IPv6
Select Block connection
Provide a suitable name and finish
Repeat the above for Outbound Rules
Now if we try to access the website www.android.com , it would be blocked


practical 9
Aim:intrusion detection system
command
sudo apt-get install snort
ifconfig
sudo nano /etc/snort/snort.conf
sudo snort -A console -l ens33 -c /etc/snort/snort.conf
then open cmd terminal and enter
Namp ip address


practical 10
Aim:web security with SSL/TLS
Description:
Web Security with SSL/TLS involves securing web communications by encrypting data transmitted between clients
and servers.This is achieved through the implementation of SSL (Secure Sockets Layer) or 
TLS (Transport Layer Security) protocols, which ensure the confidentiality, integrity, 
and authenticity of the data. Proper certificate management and secure session establishment are 
essential components of this process to protect against eavesdropping, tampering, and forgery.
Procedure:
Obtain an SSL/TLS Certificate:
Choose a Certificate Authority (CA) to obtain a trusted SSL/TLS certificate.
Generate a Certificate Signing Request (CSR) from your server.
Submit the CSR to the CA and follow their validation process.
Download the issued certificate along with any intermediate certificates.
Install the Certificate on the Server:
Access your web server's configuration files.
Upload the SSL/TLS certificate and the corresponding private key to the server.
Configure your web server (e.g., Apache, Nginx) to use the certificate by modifying the configuration files to include paths to the certificate and private key.
Enable HTTPS and Redirect HTTP Traffic:
Update your web server configuration to listen for HTTPS traffic on port 443.
Set up redirection rules to automatically redirect all HTTP traffic (port 80) to HTTPS to ensure secure communication.
Test the Configuration:
Use tools like SSL Labs’ SSL Test or other online tools to verify that the SSL/TLS certificate is correctly installed and that your server is secure.
Check for common vulnerabilities and ensure that secure ciphers and protocols are enabled.
Maintain and Renew Certificates:
Keep track of your certificate's expiration date and set reminders for renewal.
Regularly update your SSL/TLS configuration to adhere to best practices and to address any vulnerabilities as they are discovered.


