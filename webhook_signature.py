from abc import ABCMeta
import hmac
import hashlib
from .util.util import Util
import time

class WebhookSignature(metaclass=ABCMeta):
    EXPECTED_SCHEME = 's'
    
    @classmethod
    def verify_header(cls, payload, header, secret, tolerance=None):
        timestamp = cls.__get_timestamp(header)
        signatures = cls.__get_signatures(header, scheme=cls.EXPECTED_SCHEME)
        print('tiemstamp', timestamp)
        print('signatures=', signatures)
        if timestamp == -1:
            # todo: raise exception
            print('SignatureVerification Error: Unable to extract timestamp and signatures from header')
        
        if not signatures:
            # todo: raise exception
            print('SignatureVerification Error: No signatures found with expected scheme')
        
        signed_payload = str(timestamp) + '.' + str(payload)
        print('signed_payload', signed_payload)
        expected_signature = cls.__compute_signature(signed_payload, secret)
        signature_found = False
        for signature in signatures:
            print('EXPECTED SIGNATURE', expected_signature)
            print('SIGNATURE', signature)
            if Util.secure_compare(expected_signature, signature):
                signature_found = True
                break
        
        if not signature_found:
            # todo: raise exception
            print('SignatureVerification Error: No signatures found matching the expected signature for payload')
            
        # Check if timestamp is within tolerance
        if ((tolerance > 0) and (abs(time.time() - timestamp) > tolerance)):
            # todo: raise exception
            print('SignatureVerification Error: Timestamp outside the tolerance zone')
        
        return True
        
    @staticmethod
    def __get_timestamp(header):
        items = header.split(',')
        for item in items:
            item_parts = item.split('=', maxsplit=1)
            if item_parts[0] == 't':
                if not item_parts[1].isnumeric():
                    return -1
                return int(item_parts[1])
        return -1
    
    @staticmethod
    def __get_signatures(header, scheme):
        signatures = []
        items = header.split(',')
        for item in items:
            item_parts = item.split('=', maxsplit=1)
            if item_parts[0] == scheme:
                signatures.append(item_parts[1])
        return signatures
        
    @staticmethod
    def __compute_signature(payload, secret):
        return hmac.new(
            bytes(secret, 'latin-1'), 
            msg=bytes(payload, 'latin-1'), 
            digestmod=hashlib.sha256
            ).hexdigest()
        