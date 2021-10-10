from random import randint
from sys import maxsize
from Crypto.Cipher import AES
from uuid import uuid4
from enum import Enum
import json

class ProtocolState(Enum):
    UNKNOWN = 0
    SENT_INIT = 1
    RECEIVED_INIT_REPLY = 2
    RECEIVED_INIT = 3
    SENT_INIT_REPLY = 4
    END = 5

class MsgType(Enum):
    UNKNOWN = 0
    INIT = 1
    INIT_REPLY = 2
    END = 3
    REGULAR = 4
    
    

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, sharedKey, name):
        self._key = None
        self.g = 627 # Public knowledge.
        self.p = 941 # Public knowledge.
        self.private_key = randint(0, maxsize)
        self.shared_key = sharedKey
        self.name = name
        self.state = ProtocolState.UNKNOWN


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        nonce = self._makeNewNonce()
        payload = {"nonce": nonce, "name": self.name, "type": MsgType.INIT}
        return json.dumps(payload)
    
    def setProtocolState(self, state):
        self.state = state

    def _makeNewNonce(self):
        return uuid4().bytes + uuid4().bytes + uuid4().bytes + uuid4().bytes 

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        payload = {}
        type = payload["type"]
        return self._isExpectedMsgType(type) and self._isValidMsgFormat(type, payload)

    
    """
    Message formats in JSON 
    INIT: {name: "client"|"server", nonce: int}
    INIT_REPLY: {nonce: int, encrypted: E({name: "client"|"server", dh: int, nonce: int}, K_ab)}
    END: {encrypted: E({name: "client"|"server", dh: int, nonce: int}, K_ab)}
    """
    def _isValidMsgFormat(self, type, payload):
        validations = []
        if type == MsgType.INIT:
            is_valid_name = payload["name"] == "client" or payload["name"] == "server"
            is_valid_nonce = payload["nonce"].isnumeric()
            validations.extend([is_valid_name, is_valid_nonce])
        elif type == MsgType.INIT_REPLY:
            is_valid_nonce = payload["nonce"].isnumeric()
            reply_nonce = payload["reply_nonce"]
            is_valid_name = payload["name"] == "client" or payload["name"] == "server"
            is_valid_reply_nonce = reply_nonce.isnumeric() and int(reply_nonce) == self.sent_nonce

            


    def _isValidStateTransition(self, type):
        pass
    
    def _getNextState(self):
        pass

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        # use if you want 
        # cipher = AES.new(self.sharedKey, AES.MODE_CTR, nonce=nonce)
        # cipher.encrypt_and_digest(plain_text)
        # cipher.decrypt(ciphertext)
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
