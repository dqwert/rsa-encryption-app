import sys
import threading

from PyQt5 import QtWidgets
import rsa
from rsa_encryption import RSATool, PublicKeyInfo

import PyQt5
from PyQt5 import Qt, QtGui


class DecryptionGroup(QtWidgets.QGroupBox):
    def __init__(self, *args, **kwargs):
        super(DecryptionGroup, self).__init__(*args, **kwargs)

        self.layout = QtWidgets.QVBoxLayout()

        self.keypair_statues = QtWidgets.QLabel('Keypair: Empty\n'
                                                'Generating keypair longer than 2048 bits takes a long time.')

        self.keypair_control = QtWidgets.QHBoxLayout()
        self.keypair_bit_num = QtWidgets.QComboBox()
        self.gen_keypair_button = QtWidgets.QPushButton('Generate new keypair')

        self.copy_pub_key_btn = QtWidgets.QPushButton('copy_pub_key')

        self.encrypted = QtWidgets.QTextEdit()

        self.decrypt = QtWidgets.QPushButton('Waiting for keypair')
        self.decrypted = QtWidgets.QTextEdit()
        self.copy_decrypted_btn = QtWidgets.QPushButton('copy_decrypted')

        self._setup_layout()
        self._setup_widgets()

    def _setup_widgets(self):
        self.keypair_bit_num.addItems((str(2 ** i) for i in range(9, 16)))
        self.keypair_bit_num.setCurrentIndex(1)

        self.encrypted.setPlaceholderText('Encrypted message')
        self.decrypted.setPlaceholderText('Decrypted message will be here')

    def _setup_layout(self):
        # setup keypair_statues
        self.layout.addWidget(self.keypair_statues)
        # setup keypair_control
        # setup  keypair_bit_num
        self.keypair_control.addWidget(self.keypair_bit_num)
        # setup  gen_keypair_button
        self.keypair_control.addWidget(self.gen_keypair_button)

        self.layout.addLayout(self.keypair_control)
        # setup copy_pub_key
        self.layout.addWidget(self.copy_pub_key_btn)
        # setup msg
        self.encrypted.setPlaceholderText('Message to encrypt')
        self.layout.addWidget(self.encrypted)
        # setup encrypt
        self.layout.addWidget(self.decrypt)
        # setup encrypted
        self.decrypted.setReadOnly(True)
        self.layout.addWidget(self.decrypted)
        # setup copy_encrypted_btn
        self.layout.addWidget(self.copy_decrypted_btn)

        self.setLayout(self.layout)


class PublicKeyListControl(QtWidgets.QWidget):
    def __init__(self, pub_key_list_data, *args, **kwargs):
        super(PublicKeyListControl, self).__init__(*args, **kwargs)

        self.layout = QtWidgets.QVBoxLayout()

        self.pub_key_list = QtWidgets.QListWidget()

        self.copy_button = QtWidgets.QPushButton('copy')
        self.remove_button = QtWidgets.QPushButton('remove')

        self.pub_key_input = QtWidgets.QTextEdit('Public key input')

        self.add_button = QtWidgets.QPushButton('add')
        self.remove_if_exist_button = QtWidgets.QPushButton('remove if exist')

        self.exist_keys_control = QtWidgets.QHBoxLayout()
        self.new_key_control = QtWidgets.QHBoxLayout()

        self._setup_layout()
        self._setup_widgets()

    def _setup_widgets(self):
        pass

    def _setup_layout(self):
        # setup pub_key_list
        self.layout.addWidget(self.pub_key_list)
        # setup exist_keys_control
        # setup  copy_button
        self.exist_keys_control.addWidget(self.copy_button)
        # setup  remove_button
        self.exist_keys_control.addWidget(self.remove_button)
        self.layout.addLayout(self.exist_keys_control)
        # setup input
        self.layout.addWidget(self.pub_key_input)
        # setup new_key_control
        # setup  add_button
        self.new_key_control.addWidget(self.add_button)
        # setup  remove_if_exist_button
        self.new_key_control.addWidget(self.remove_if_exist_button)
        self.layout.addLayout(self.new_key_control)
        # setup
        self.setLayout(self.layout)


class EncryptionDisplay(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super(EncryptionDisplay, self).__init__(*args, **kwargs)

        self.layout = QtWidgets.QVBoxLayout()

        self.msg = QtWidgets.QTextEdit()
        self.encrypt = QtWidgets.QPushButton('Waiting for keypair')
        self.encrypted = QtWidgets.QTextEdit()
        self._setup_layout()
        self._setup_widgets()

    def _setup_widgets(self):
        self.msg.setPlaceholderText('Message to encrypt')
        self.encrypted.setPlaceholderText('Encrypted will display here')

    def _setup_layout(self):
        self.layout.addWidget(self.msg)
        self.layout.addWidget(self.encrypt)
        self.layout.addWidget(self.encrypted)

        self.setLayout(self.layout)


class EncryptionGroup(QtWidgets.QGroupBox):
    def __init__(self, *args, **kwargs):
        super(EncryptionGroup, self).__init__(*args, **kwargs)

        self.layout = QtWidgets.QHBoxLayout()

        self.pub_key_control = PublicKeyListControl(None)
        self.encryption_display = EncryptionDisplay()
        self._setup_layout()
        self._setup_widgets()

    def _setup_widgets(self):
        pass

    def _setup_layout(self):
        self.layout.addWidget(self.pub_key_control)
        self.layout.addWidget(self.encryption_display)

        self.setLayout(self.layout)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("RSA over Chat")

        self.decryption_group = DecryptionGroup('Decryption')
        self.encryption_group = EncryptionGroup('Encryption')

        layout = QtWidgets.QHBoxLayout()
        layout.addWidget(self.decryption_group)
        layout.addWidget(self.encryption_group)

        widget = QtWidgets.QWidget()
        widget.setLayout(layout)

        self.setCentralWidget(widget)


class RsaEncryptionGui:
    def __init__(self):
        self.rsa_tool = RSATool()

        self.gui = QtWidgets.QApplication(sys.argv)
        self.window = MainWindow()

        self._wire()

        self.window.show()
        self.gui.exec_()

    def _wire(self):
        self.window.decryption_group.keypair_bit_num.currentTextChanged.connect(lambda s: print(s))
        self.window.decryption_group.gen_keypair_button.clicked.connect(self._gen_keypair)
        self.window.decryption_group.gen_keypair_button.clicked.connect(
            lambda _: self.window.decryption_group.gen_keypair_button.setDisabled(True))
        self.window.decryption_group.decrypt.clicked.connect(self._decrypt)

        self.window.encryption_group.encryption_display.encrypt.clicked.connect(self._encrypt)
        self.window.encryption_group.pub_key_control.copy_button.clicked.connect(self._copy_pub_key)

    def _gen_keypair(self):
        bit_num = int(self.window.decryption_group.keypair_bit_num.currentText())
        self.window.decryption_group.keypair_statues.setText('Keypair: Generating')
        self.rsa_tool.gen_keypair(bit_num)
        self.rsa_tool.add_public_key(self.rsa_tool.pri_key, 'Your current public key')
        self._update_pub_key_list()
        self.window.decryption_group.keypair_statues.setText('Keypair: Ready')
        self.window.decryption_group.decrypt.setText('Decrypt')
        self.window.encryption_group.encryption_display.encrypt.setText('Encrypt')

    def _decrypt(self):
        try:
            encrypted = bytearray.fromhex(self.window.decryption_group.encrypted.toPlainText())
            print(encrypted)
            decrypted = self.rsa_tool.decrypt_msg(encrypted)
            self.window.decryption_group.decrypted.setText(decrypted)
        except FileNotFoundError:
            self.window.decryption_group.decrypted.setText('Empty keypair: no private key available')

    def _encrypt(self):
        msg = self.window.encryption_group.encryption_display.msg.toPlainText()
        encrypted = self.rsa_tool.encrypt_msg(msg)
        print(encrypted)
        self.window.encryption_group.encryption_display.encrypted.setText(encrypted.hex())

    def _update_pub_key_list(self):
        self.window.encryption_group.pub_key_control.pub_key_list.clear()
        for public_key_info in self.rsa_tool.pub_keys_info:
            self.window.encryption_group.pub_key_control.pub_key_list.addItem(public_key_info.name)

    def _add_pub_key(self):
        public_key = bytearray.fromhex(self.window.encryption_group.pub_key_control.pub_key_input.toPlainText())

    def _copy_pub_key(self):
        index_selected = self.window.encryption_group.pub_key_control.pub_key_list.currentIndex().row()
        if index_selected == -1:
            return
        # self.clipboard.setText(self.rsa_tool.pub_keys_info[index_selected].name, Qt.QClipboard.Clipboard)
        # PyQt5.setText(self.rsa_tool.pub_keys_info[index_selected].name, Qt.QClipboard.Clipboard)


if __name__ == '__main__':
    application = RsaEncryptionGui()
