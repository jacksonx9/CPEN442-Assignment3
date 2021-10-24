from random import randint
from sys import maxsize
from Crypto.Cipher import AES
from uuid import uuid4
from enum import IntEnum
import json

class MsgType(IntEnum):
    INIT = 1
    INIT_REPLY = 2
    END = 3
    
    

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.g = 627 # Public knowledge.
        self.p = 941 # Public knowledge.
        self.private_key = randint(0, maxsize)
        self._sent_nonce = None
        self._name = "server"
        self.session_key = -1


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
        encrypted_payload = self._EncryptWithSymmetric(json.dumps({"name": self._name, "nonce": message["nonce"], "dh": dh_val}))
        payload = {"nonce": nonce, "encrypted": encrypted_payload, "type": MsgType.INIT_REPLY}
        return json.dumps(payload)


    def GetProtocolEndMessage(self, message):
        decoded_payload = json.loads(self._DecryptWithSymmetric(message["encrypted"]))
        if self._sent_nonce != decoded_payload["nonce"]:
            return None

        dh_val = pow(self.g, self.private_key, self.p)
        self.session_key = pow(decoded_payload["dh"], self.private_key, self.p)
        print(self.session_key)
        encrypted_payload = self._EncryptWithSymmetric(json.dumps({"name": self._name, "nonce": message["nonce"], "dh": dh_val}))
        payload = {"encrypted": encrypted_payload, "type": MsgType.END}
        return json.dumps(payload)

    def VerifyProtocolEndMessage(self, message):
        decoded_payload = json.loads(self._DecryptWithSymmetric(message["encrypted"]))
        if self._sent_nonce != decoded_payload["nonce"]:
            return None
        print("heregang")
        self.session_key = pow(decoded_payload["dh"], self.private_key, self.p)
        print(self.session_key)
    

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        print("aaa", message)
        # print(message[])
        message_type = message["type"]
        return self._isProtocolType(message_type) 
    
    def _isProtocolType(self, type):
    	# return IntEnum(type) in set(MsgType.INIT, MsgType.INIT_REPLY, MsgType.END)
    	return type in range(1,4)
    	# return type in set(MsgType.INIT, MsgType.INIT_REPLY, MsgType.END)
    
    """
    Message formats in JSON 
    INIT: {name: "client"|"server", nonce: int, type: MsgType}
    INIT_REPLY: {nonce: int, encrypted: E({name: "client"|"server", dh: int, nonce: int}, K_ab)}
    END: {encrypted: E({name: "client"|"server", dh: int, nonce: int}, K_ab)}
    REGULAR: {ecrypted: E(str)}
    """
    def _isValidMsgFormat(self, type, payload):
        validations = []
        if type == MsgType.INIT:
            is_valid_name = payload["name"] == "client" or payload["name"] == "server"
            is_valid_nonce = payload["nonce"].isnumeric()
            
            validations.extend([is_valid_name, is_valid_nonce])
        elif type == MsgType.INIT_REPLY:
            is_valid_nonce = payload["nonce"].isnumeric()
            encrypted = payload["encrypted"]
            is_valid_reply_name = encrypted["name"] == "client" or encrypted["name"] == "server"
            is_valid_reply_nonce = encrypted["nonce"].isnumeric() and int(encrypted["nonce"]) == self._sent_nonce
            is_valid_dh = encrypted["dh"].isnumeric()
            
            validations.extend([is_valid_nonce, is_valid_reply_name, is_valid_reply_name, is_valid_dh])
        elif type == MsgType.END:
            encrypted = payload["encrypted"]
            is_valid_reply_name = encrypted["name"] == "client" or encrypted["name"] == "server"
            is_valid_reply_nonce = encrypted["nonce"].isnumeric() and int(encrypted["nonce"]) == self._sent_nonce
          	
            validations.extend([is_valid_reply_name, is_valid_reply_nonce])
		#TODO: continue one guys!
        return all(validations)

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
      	#self._isValidMsgFormat(type, payload)
        message_type = message["type"]
        print("in Process", message)
        print("in Process2", message_type == MsgType.INIT)
        if message_type == MsgType.INIT:
            # Recieve “I’m client “ + R_A
            # Respond with Rb, E(“server”+ g^b mod p + Ra, Kab)
            print("Nonce1 is ", message["nonce"])
            return self.GetProtocolInitResponseMessage(message)
        elif message_type == MsgType.INIT_REPLY:
            # Recieve Respond with Rb, E(“server”, g^b mod p, Ra, Kab)
            # Respond E(“client”, g^a mod p, Rb, Kab)
            return self.GetProtocolEndMessage(message)
        else:
            # Recieve E(“client”+ g^a mod p + Rb, Kab)
            return self.VerifyProtocolEndMessage(message)


    def SetSecret(self, key):
        self._shared_key = key
        pass

    def SetName(self, name):
        self._name = name
        pass

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    def _EncryptWithSymmetric(self, plain_text):
        cipher_text = plain_text
        # Only encrypt is session key exists
        # use if you want 
        # cipher = AES.new(self._shared_key, AES.MODE_CTR, nonce=nonce)
        # cipher.encrypt_and_digest(plain_text)
        return cipher_text

    def _DecryptWithSymmetric(self, cipher_text):
        # Only encrypt is session key exists
        # cipher = AES.new(self._shared_key, AES.MODE_CTR, nonce=nonce)
        # print(cipher.decrypt(cipher_text))
        #cipher.decrypt(cipher_text)
        return cipher_text


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        # Only encrypt if message type in payload is defined and INIT or END etc.
        # use if you want 
        # cipher = AES.new(self._shared_key, AES.MODE_CTR, nonce=nonce)
        # cipher.encrypt_and_digest(plain_text)
        # cipher.decrypt(ciphertext)
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
