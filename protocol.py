from random import randint
from sys import maxsize
# from Crypto.Cipher import AES
from uuid import uuid4
from enum import IntEnum
import json

class ProtocolState(IntEnum):
    UNKNOWN = 0
    SENT_INIT = 1
    RECEIVED_INIT_REPLY = 2
    RECEIVED_INIT = 3
    SENT_INIT_REPLY = 4
    END = 5

class MsgType(IntEnum):
    UNKNOWN = 0
    INIT = 1
    INIT_REPLY = 2
    END = 3
    REGULAR = 4
    
    

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.g = 627 # Public knowledge.
        self.p = 941 # Public knowledge.
        self.private_key = randint(0, maxsize)
        self.state = ProtocolState.UNKNOWN
        self.sent_nonce = None
        self._name = "Server"


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        nonce = self._makeNewNonce()
        self.sent_nonce = nonce
        payload = {"nonce": nonce, "name": self._name, "type": MsgType.INIT}
        return json.dumps(payload)
    
    def setProtocolState(self, state):
        self.state = state

    def _makeNewNonce(self):
        return randint(0, maxsize)
        # return uuid4().bytes + uuid4().bytes + uuid4().bytes + uuid4().bytes 

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
            is_valid_reply_nonce = encrypted["nonce"].isnumeric() and int(encrypted["nonce"]) == self.sent_nonce
            is_valid_dh = encrypted["dh"].isnumeric()
            
            validations.extend([is_valid_nonce, is_valid_reply_name, is_valid_reply_name, is_valid_dh])
        elif type == MsgType.END:
            encrypted = payload["encrypted"]
            is_valid_reply_name = encrypted["name"] == "client" or encrypted["name"] == "server"
            is_valid_reply_nonce = encrypted["nonce"].isnumeric() and int(encrypted["nonce"]) == self.sent_nonce
          	
            validations.extend([is_valid_reply_name, is_valid_reply_nonce])
		#TODO: continue one guys!
        return all(validations)

            


    def _isValidStateTransition(self, type):
        pass
    
    def _getNextState(self):
        if self.state == ProtocolState.UNKNOWN:
            # TODO dont hardcode these strings
            if self._name == "client":
                return ProtocolState.RECEIVED_INIT
            elif self._name == "server":
                return ProtocolState.SENT_INIT
            else:
                raise Exception("Invalid name")
 
        if self.state == ProtocolState.SENT_INIT:
            return ProtocolState.RECEIVED_INIT_REPLY
        elif self.state == ProtocolState.RECEIVED_INIT_REPLY:
            return ProtocolState.END
        elif self.state == ProtocolState.RECEIVED_INIT:
            return ProtocolState.SENT_INIT_REPLY
        elif self.state == ProtocolState.SENT_INIT_REPLY:
            return ProtocolState.END
        else:
            raise Exception("Invalid current protocol state")

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
      	#self._isValidMsgFormat(type, payload)
        message_type = message["type"]
        print("in Process", message)
        if message_type == MsgType.INIT: 
            # Recieve “I’m Client “ + R_A
            # Respond with Rb, E(“Server”+ g^b mod p + Ra, Kab)
            pass
        elif message_type == MsgType.INIT_REPLY:
            # Recieve Respond with Rb, E(“Server”+ g^b mod p + Ra, Kab)
            # Respond E(“Client”+ g^a mod p + Rb, Kab)
            pass
        else:
            # Recieve E(“Client”+ g^a mod p + Rb, Kab)
            pass


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


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
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
