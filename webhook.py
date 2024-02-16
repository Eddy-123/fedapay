from abc import ABCMeta
from .webhook_signature import WebhookSignature

class Webhook(metaclass=ABCMeta):
    DEFAULT_TOLERANCE=300
    
    @staticmethod
    def construct_event(payload, signature_header, secret, tolerance=DEFAULT_TOLERANCE):
        WebhookSignature.verify_header(payload, signature_header, secret, tolerance)