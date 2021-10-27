from random import randint, getrandbits
from sys import maxsize
from tkinter.constants import E
from Cryptodome.Cipher import AES
from enum import IntEnum
import json
import hashlib
from base64 import b64encode, b64decode

from p import p

class MsgType(IntEnum):
    INIT = 1
    INIT_REPLY = 2
    END = 3
    GENERAL = 4

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self.g = 2 # Public knowledge.
        self.p = p # Public knowledge.
        self.private_key = getrandbits(4096)
        self._sent_nonce = None
        self._name = "server"
        self._session_key = -1
        self._next_state = MsgType.INIT


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):

        nonce = randint(0, maxsize)
        self._sent_nonce = nonce
        payload = {"nonce": nonce, "name": self._name, "type": MsgType.INIT}
        
        return json.dumps(payload)

    def GetProtocolInitResponseMessage(self, message):
        nonce = randint(0, maxsize)
        self._sent_nonce = nonce
        dh_val = pow(self.g, self.private_key, self.p)

        payload = self.EncryptAndProtectMessage(json.dumps({"name": self._name, "nonce": message["nonce"], "dh": dh_val}), MsgType.INIT_REPLY, False, nonce)

        return payload


    def GetProtocolEndMessage(self, message):
        decoded_payload = self.DecryptAndVerifyMessage(message, False)

        if self._sent_nonce != decoded_payload["nonce"]:
            raise ValueError("INTEGRITY ERROR; GetProtocolEndMessage")

        dh_val = pow(self.g, self.private_key, self.p)
        self.SetSessionKey(pow(decoded_payload["dh"], self.private_key, self.p))
        payload = self.EncryptAndProtectMessage(json.dumps({"name": self._name, "nonce": message["nonce"], "dh": dh_val}), MsgType.END, False)
        return payload

    def VerifyProtocolEndMessage(self, message):
        decoded_payload = self.DecryptAndVerifyMessage(message, False)

        if self._sent_nonce != decoded_payload["nonce"]:
            raise ValueError("INTEGRITY ERROR; VerifyProtocolEndMessage")

        self.SetSessionKey(pow(decoded_payload["dh"], self.private_key, self.p))
        print("heregang")
    

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        message_type = message["type"]
        return self._isProtocolType(message_type) 
    
    def _isProtocolType(self, type):
        return MsgType(type) in {MsgType.INIT, MsgType.INIT_REPLY, MsgType.END}
        # return type in range(1,4)
        # return type in set(MsgType.INIT, MsgType.INIT_REPLY, MsgType.END)
    
    """
    Message formats in JSON 
    INIT: {name: "client" or "server", nonce: int, type: MsgType}
    INIT_REPLY: {nonce: int, encrypted: E({name: "client" or "server", dh: int, nonce: int}, K_ab)}
    END: {encrypted: E({name: "client" or "server", dh: int, nonce: int}, K_ab)}
    GENERAL: {ecrypted: E(str)}
    """
    def _isValidMsgFormat(self, payload):
        msg_type = None
        if "type" in payload:
            msg_type = payload["type"]
        else:
            return False

        validations = []
        if msg_type == MsgType.INIT:
            is_valid_name = payload["name"] == "client" or payload["name"] == "server"
            is_valid_nonce = type(payload["nonce"]) == int

            validations.extend([is_valid_name, is_valid_nonce])
        elif msg_type == MsgType.INIT_REPLY:
            is_valid_nonce = type(payload["nonce"]) == int
            is_valid_encrypted = "encrypted" in payload
            
            validations.extend([is_valid_nonce, is_valid_encrypted])

        elif msg_type == MsgType.END:
            is_valid_encrypted = "encrypted" in payload
        
            validations.extend([is_valid_encrypted])

        elif msg_type == MsgType.GENERAL:
            is_valid_encrypted = "encrypted" in payload
        
            validations.extend([is_valid_encrypted])
        #TODO: continue one guys!
        return all(validations)


    def _verifyMsg(self, msg_type, decrypted):
        validations = []

        if msg_type == MsgType.INIT_REPLY or msg_type == MsgType.END:
            is_valid_reply_name = decrypted["name"] == "client" or decrypted["name"] == "server"
            is_valid_reply_nonce = type(decrypted["nonce"]) == int and decrypted["nonce"] == self._sent_nonce
            is_valid_dh = type(decrypted["dh"]) == int
            
            validations.extend([is_valid_reply_name, is_valid_reply_nonce, is_valid_dh])


        elif msg_type == MsgType.GENERAL:
            # TODO: check decrypted decrypted
            is_valid_message = decrypted.isalnum()
            
            validations.extend([is_valid_message])

        #TODO: continue one guys!
        return all(validations)

    #TODO: Make sending message work without securing connection

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        if not self._isValidMsgFormat(message):
            raise ValueError("Invalid Message Format")

        message_type = message["type"]

        if message_type == MsgType.INIT:
            # Recieve “I’m client “ + R_A
            # Respond with Rb, E(“server”+ g^b mod p + Ra, Kab)
            return self.GetProtocolInitResponseMessage(message)
        elif message_type == MsgType.INIT_REPLY:
            # Recieve Respond with Rb, E(“server”, g^b mod p, Ra, Kab)
            # Respond E(“client”, g^a mod p, Rb, Kab)
            return self.GetProtocolEndMessage(message)
        else:
            # Recieve E(“client”+ g^a mod p + Rb, Kab)
            self.VerifyProtocolEndMessage(message)


    def SetSecret(self, key):
        self._shared_key = hashlib.md5(key.encode()).digest()

    def SetName(self, name):
        self._name = name

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._session_key = hashlib.md5(str(key).encode()).digest()

    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text, type = MsgType.GENERAL, use_session_key = True, nonce = None):
        # Only encrypt if message type in payload is defined and INIT or END etc.
        # use if you want
        key = self._session_key if use_session_key else self._shared_key
        cipher = AES.new(key, AES.MODE_EAX)
        encoded_message, tag = cipher.encrypt_and_digest(plain_text.encode())

        cipher_text = {"encrypted": b64encode(encoded_message).decode('utf-8'), "aes_nonce": b64encode(cipher.nonce).decode('utf-8'), "tag": b64encode(tag).decode('utf-8'), "type": type}
        
        if nonce is not None:
            cipher_text["nonce"] = nonce
        return json.dumps(cipher_text)


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text_json, use_session_key = True):
        encrypted_message = b64decode(cipher_text_json["encrypted"])
        aes_nonce = b64decode(cipher_text_json["aes_nonce"])
        tag = b64decode(cipher_text_json["tag"])

        key = self._session_key if use_session_key else self._shared_key

        cipher = AES.new(key, AES.MODE_EAX, nonce=aes_nonce)
        plain_text = cipher.decrypt(encrypted_message)

        cipher.verify(tag)
        
        decoded_text = plain_text.decode()
        
        if not use_session_key:
            decoded_text = json.loads(decoded_text)

        if not self._verifyMsg(cipher_text_json["type"], decoded_text):
            raise ValueError("Invalid Message Contents")
        return decoded_text


