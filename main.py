import rsa
from Crypto.Cipher import DES

publicKey = None
privateKey = None


def main():
    main_menu()


def main_menu():
    choice = input("""
		Choose Key action:


                1: Generate RSA Keys
                2: Import RSA Keys
                3: DES encrypt
                4: DES decrypt
                5: Exit

            Please enter your choice: """)

    des_selected = False
    if choice == '1':
        des_selected = False
        generate_keys()
    elif choice == '2':
        des_selected = False
        import_keys()
    elif choice == '3':
        des_selected = True
        des_encrypt()
    elif choice == '4':
        des_selected = True
        des_decrypt()
    elif choice == '5':
        exit()

    while True and not des_selected:
        second_menu()


def generate_keys():
    global publicKey, privateKey
    (publicKey, privateKey) = rsa.newkeys(1024)
    print("\n\nYours RSA Public Key:\n\n", publicKey.save_pkcs1('PEM').decode("utf-8"))
    print("\nYours RSA Private Key:\n\n", privateKey.save_pkcs1('PEM').decode("utf-8"))


def import_keys():
    global privateKey, publicKey
    pub = open("public.pub", "rb")
    priv = open("private.peb", "rb")
    publicKey = rsa.PublicKey.load_pkcs1(pub.read(), "PEM")
    privateKey = rsa.PrivateKey.load_pkcs1(priv.read(), "PEM")
    pub.close()
    priv.close()
    print("\n\nYours RSA Public Key:\n\n", publicKey.save_pkcs1('PEM').decode("utf-8"))
    print("\nYours RSA Private Key:\n\n", privateKey.save_pkcs1('PEM').decode("utf-8"))


def des_encrypt():
    inputString = input("Input your string for crypt: ").encode("utf-8")
    inputPassword = input("Input your encryption password: ").encode("utf-8")
    des = DES.new(inputPassword, DES.MODE_ECB)
    encryptedString = des.encrypt(inputString)
    print("\n\nYour encrypted string: ", ' '.join('{0:08b}'.format(x, 'b') for x in encryptedString))
    print("\n\nYour encryped string in HEX format: ", encryptedString.hex())


def des_decrypt():
    inputString = input("Input your DES encrypted HEX string: ")
    inputPassword = input("Input your encryption password: ").encode("utf-8")
    des = DES.new(inputPassword, DES.MODE_ECB)
    decryptedString = des.decrypt(bytes.fromhex(inputString))
    print("\n\nYour decrypted string: ", decryptedString)


def second_menu():
    choice = input("""
		Choose action:


                1: Encrypt string
                2: Decrypt string
                3: Sign string
                4: Verify signature
                5: Save keys to files
                6: Exit

            Please enter your choice: """)
    if choice == '1':
        encrypt_string()
    elif choice == '2':
        decrypt_string()
    elif choice == '3':
        sign_string()
    elif choice == '4':
        verify_signature()
    elif choice == '5':
        save_keys()
    elif choice == '6':
        exit()


def encrypt_string():
    global publicKey
    inputString = input("Please input your string for encryption: ")
    cryptedString = rsa.encrypt(inputString.encode("utf-8"), publicKey)
    print("\n\nYour encrypted string is: ", cryptedString.hex())


def decrypt_string():
    global privateKey
    inputString = input("Please input your encrypted string in HEX format: ")
    decryptedString = rsa.decrypt(bytes.fromhex(inputString), privateKey)
    print("\n\nYour decrypted string is: ", decryptedString.decode("utf-8"))


def sign_string():
    global privateKey
    inputString = input("Please input your message for signification: ").encode("utf-8")
    signature = rsa.sign(inputString, privateKey, "SHA-1")
    print("\n\nYour signature for string is: ", signature.hex())


def verify_signature():
    global publicKey
    inputString = input("Please input your message for verification: ").encode("utf-8")
    inputSignature = bytes.fromhex(input("Please input your signature for verification: "))
    result = rsa.verify(inputString, inputSignature, publicKey)
    output = "\nYour signature is {}"
    if (result):
        print(output.format("VALID"))
    else:
        print(output.format("INVALID"))


def save_keys():
    global privateKey, publicKey
    pub = open("public.pub", "wb")
    priv = open("private.peb", "wb")
    pub.write(publicKey.save_pkcs1('PEM'))
    pub.close()
    priv.write(privateKey.save_pkcs1('PEM'))
    priv.close()


main()
