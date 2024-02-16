

class WebhookSignature:
    
    def __init__(self):
        self.expected_scheme = 's'
    
    def verify_header(self, payload, signature_header, secret, tolerance):
        timestamp = self.get_timestamp(signature_header)
        signatures = self.get_signatures(signature_header, scheme=self.expected_scheme)
        if timestamp == -1:
            print('SignatureVerification Error: Unable to extract timestamp and signatures from header')
        
        if not signatures:
            print('SignatureVerification Error: No signatures found with expected scheme')
        
    def get_timestamp(self, signature_header):
        items = signature_header.split(',')
        for item in items:
            item_parts = item.split('=', maxsplit=1)
            if item_parts[0] == 't':
                if not item_parts[1].isnumeric():
                    return -1
                return int(item_parts[1])
        return -1
    
    def get_signatures(self, signature_header, scheme):
        signatures = []
        items = signature_header.split(',')
        for item in items:
            item_parts = item.split('=', maxsplit=1)
            if item_parts[0] == scheme:
                signatures.append(item_parts[1])
        return signatures
        
            