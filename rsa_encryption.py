import os
import rsa


class PublicKeyInfo:
    def __init__(self, pub_key, name):
        self.pub_key = pub_key
        self.name = name


class RSATool:
    def __init__(self):
        self.pub_keys_info = []
        self.pub_key = None
        self.pri_key = None

        self._pub_key_filename = 'r_public.pem'
        self._pri_key_filename = 'r_private.pem'

    # keypair operations
    def gen_keypair(self,  nbits=2048, accurate=True):
        (self.pub_key, self.pri_key) = rsa.newkeys(nbits, accurate=accurate)

    def clean_keypair(self):
        self.pub_key = None
        self.pri_key = None

    def save_keypair(self, path, overwrite=False, pub_key_path=None, pri_key_path=None):
        pub_key_path = pub_key_path if pub_key_path else os.path.join(path, self._pub_key_filename)
        pri_key_path = pri_key_path if pri_key_path else os.path.join(path, self._pri_key_filename)

        if (not overwrite) and (os.path.exists(pub_key_path) or os.path.exists(pri_key_path)):
            return False

        with open(pub_key_path, 'wb') as pub_key_file:
            # pub_key_data = self.pub_key.save_pkcs1()
            pub_key_data = rsa.PublicKey.save_pkcs1(self.pub_key)
            pub_key_file.write(pub_key_data)

        with open(pri_key_path, 'wb') as pri_key_file:
            # pri_key_data = self.pri_key.save_pkcs1()
            pri_key_data = rsa.PrivateKey.save_pkcs1(self.pri_key)
            pri_key_file.write(pri_key_data)

        return True

    def load_keypair(self, path, overwrite=False, pub_key_path=None, pri_key_path=None):
        pub_key_path = pub_key_path if pub_key_path else os.path.join(path, self._pub_key_filename)
        pri_key_path = pri_key_path if pri_key_path else os.path.join(path, self._pri_key_filename)

        if (not overwrite) and ((self.pub_key is not None) or (self.pri_key is not None)):
            return False

        if (not os.path.exists(pub_key_path)) or (not os.path.exists(pri_key_path)):
            return False

        with open(pub_key_path, 'rb') as pub_key_file:
            pub_key_data = pub_key_file.read()
            self.pub_key = rsa.PublicKey.load_pkcs1(pub_key_data)

        with open(pri_key_path, 'rb') as pri_key_file:
            pri_key_data = pri_key_file.read()
            self.pri_key = rsa.PrivateKey.load_pkcs1(pri_key_data)

        return True

    # encrypt & decrypt
    def encrypt_msg(self, msg: str, encoding='utf-8'):
        if not self.pub_key:
            raise FileNotFoundError('No valid public key available')

        return rsa.encrypt(msg.encode(encoding), self.pub_key)

    def decrypt_msg(self, crypto: bytes, encoding='utf-8'):
        if not self.pri_key:
            raise FileNotFoundError('No valid private key available')

        return rsa.decrypt(crypto, self.pri_key).decode(encoding)

    # misc
    def add_public_key_file(self, pub_key_file, name):
        with open(pub_key_file, 'rb'):
            pub_key_data = pub_key_file.read()
            pub_key = rsa.PublicKey.load_pkcs1(pub_key_data)
            self.pub_keys_info.append(PublicKeyInfo(pub_key, name))

    def add_public_key(self, pub_key: rsa.PublicKey, name):
        self.pub_keys_info.append(PublicKeyInfo(pub_key, name))


def main():
    rsa_tool = RSATool()
    rsa_tool.gen_keypair()

    print('rsa_tool.pri_key: ', rsa.PrivateKey.save_pkcs1(rsa_tool.pri_key))
    print('rsa_tool.pub_key: ', rsa.PublicKey.save_pkcs1(rsa_tool.pub_key))

    crypto = rsa_tool.encrypt_msg('Hello')
    print('crypto: ', crypto)

    rsa_tool.save_keypair('.', overwrite=True)
    rsa_tool.clean_keypair()
    rsa_tool.load_keypair('.', overwrite=True)

    msg = rsa_tool.decrypt_msg(crypto)
    print('msg: ', msg)


if __name__ == '__main__':
    main()
