from abc import ABCMeta
import json
        
from abc import ABCMeta
import hmac
import hashlib
from fedapay import _util
import time


class Webhook():
    DEFAULT_TOLERANCE=300
    
    @staticmethod
    def construct_event(payload, signature_header, secret, tolerance=DEFAULT_TOLERANCE):
        WebhookSignature.verify_header(payload, signature_header, secret, tolerance)
        
        data = json.loads(payload)
        return data

class WebhookSignature(metaclass=ABCMeta):
    EXPECTED_SCHEME = 's'
    
    @classmethod
    def verify_header(cls, payload, header, secret, tolerance=None):
        timestamp = cls.__get_timestamp(header)
        signatures = cls.__get_signatures(header, scheme=cls.EXPECTED_SCHEME)
        if timestamp == -1:
            # todo: raise exception
            print('SignatureVerification Error: Unable to extract timestamp and signatures from header')
        
        if not signatures:
            # todo: raise exception
            print('SignatureVerification Error: No signatures found with expected scheme')
        
        signed_payload = str(timestamp) + '.' + str(payload)
        expected_signature = cls.__compute_signature(signed_payload, secret)
        signature_found = False
        for signature in signatures:
            print('EXPECTED SIGNATURE', expected_signature)
            print('SIGNATURE', signature)
            if _util.secure_compare(expected_signature, signature):
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
           



payload = '{"name":"transaction.approved","object":"transaction","entity":{"klass":"v1/transaction","id":235879,"reference":"trx_fOg_1708343266047","amount":22000,"description":"appointment 70","callback_url":"https://sandbox-checkout.fedapay.com/transactions/callback?secured_id=\\u0026secured_id=secured_id_py4i9llfo","status":"approved","customer_id":19359,"currency_id":1,"mode":"moov","operation":"payment","metadata":{"expire_schedule_jobid":"0b45fb8a381b456b041bd064","paid_customer":{"firstname":"Jerrold","lastname":"Hilll","email":"lixoga1490@gosarlar.com"}},"commission":"0.018","fees":403,"fixed_commission":0,"amount_transferred":22000,"created_at":"2024-02-19T11:47:46.047Z","updated_at":"2024-02-19T11:48:10.408Z","approved_at":"2024-02-19T11:48:10.351Z","canceled_at":null,"declined_at":null,"refunded_at":null,"transferred_at":null,"deleted_at":null,"last_error_code":"API_ERROR","custom_metadata":null,"amount_debited":22403,"receipt_url":null,"payment_method_id":70138,"sub_accounts_commissions":null,"transaction_key":"1791327773760160","merchant_reference":null,"account_id":8202,"balance_id":142430,"customer":{"klass":"v1/customer","id":19359,"firstname":"Unknown","lastname":"Unknown","full_name":"Unknown Unknown","email":null,"account_id":8202,"phone_number_id":null,"created_at":"2024-02-19T11:47:46.042Z","updated_at":"2024-02-19T11:47:46.042Z","deleted_at":null},"currency":{"klass":"v1/currency","id":1,"name":"FCFA","iso":"XOF","code":952,"prefix":null,"suffix":"CFA","div":1,"default":true,"created_at":"2018-05-27T21:26:23.618Z","updated_at":"2023-04-25T13:45:49.805Z","modes":["mtn","cybersource","moov","mtn_ci","moov_tg","orange_ci","orange_sn","free_sn","airtel_ne","togocel","orange_ml","mtn_open","mtn_ecw","ecobank_tpe","orabank_tpe","uba","stripe_gw","uba_atm","bmo","mtn_open_ci","sbin"]},"payment_method":{"klass":"v1/payment_method","id":70138,"brand":"moov","country":"BJ","number":"22964000001","deleted_at":null,"created_at":"2024-02-19T11:48:09.826Z","updated_at":"2024-02-19T11:48:09.826Z","method":"phone"},"balance":{"klass":"v1/balance","id":142430,"amount":474000,"mode":"moov","created_at":"2024-01-27T17:22:46.921Z","updated_at":"2024-01-27T17:22:46.921Z"},"refunds":[]},"account":{"klass":"v1/account","id":8202,"name":"Mon compte","timezone":"UTC","country":"BJ","created_at":"2024-01-27T17:22:46.777Z","updated_at":"2024-02-09T10:15:32.726Z","verified":false,"reference":"acc_4888146135","business_type":null,"business_identity_type":null,"business_identity_number":null,"business_vat_number":null,"business_registration_number":null,"business_category":null,"blocked":false,"business_website":null,"business_address":null,"business_name":null,"business_phone":null,"business_email":null,"business_owner":null,"business_company_capital":null,"business_description":null,"submitted":false,"reject_reason":null,"has_balance_issue":true,"last_balance_issue_checked_at":"2024-02-09T10:15:31.798Z","prospect_code":null,"deal_closer_code":null,"manager_code":null,"business_identity_id":null,"business_vat_id":null,"business_registration_id":null,"business_owner_signature_id":null,"business_identity":null,"business_vat":null,"business_registration":null,"business_owner_signature":null,"user_accounts":[{"klass":"v1/user_account","id":8237,"account_id":8202,"user_id":7881,"role_id":1}],"users":[{"klass":"v1/user","id":7881,"email":"lixoga1490@gosarlar.com","confirmed_at":"2024-01-27T17:24:34.268Z","reset_sent_at":null,"admin":false,"admin_role":"user","created_at":"2024-01-27T17:22:46.755Z","updated_at":"2024-01-27T17:24:34.277Z","firstname":"Eddy","lastname":"Adegnandjou","locale":"fr","two_fa_enabled":false}],"api_keys":[{"klass":"v1/api_key","id":8807,"created_at":"2024-01-27T17:22:47.681Z","updated_at":"2024-01-27T17:22:47.681Z","public_key":"pk_sandbox_NVGMAJZFlVlhg2rU5YzgI2xY"}],"balances":[{"klass":"v1/balance","id":142444,"amount":0,"mode":"sbin","created_at":"2024-01-27T17:22:47.668Z","updated_at":"2024-01-27T17:22:47.668Z"},{"klass":"v1/balance","id":142443,"amount":0,"mode":"bmo","created_at":"2024-01-27T17:22:47.599Z","updated_at":"2024-01-27T17:22:47.599Z"},{"klass":"v1/balance","id":142442,"amount":0,"mode":"uba_atm","created_at":"2024-01-27T17:22:47.559Z","updated_at":"2024-01-27T17:22:47.559Z"},{"klass":"v1/balance","id":142441,"amount":0,"mode":"uba","created_at":"2024-01-27T17:22:47.478Z","updated_at":"2024-01-27T17:22:47.478Z"},{"klass":"v1/balance","id":142440,"amount":0,"mode":"orabank_tpe","created_at":"2024-01-27T17:22:47.435Z","updated_at":"2024-01-27T17:22:47.435Z"},{"klass":"v1/balance","id":142439,"amount":0,"mode":"ecobank_tpe","created_at":"2024-01-27T17:22:47.395Z","updated_at":"2024-01-27T17:22:47.395Z"},{"klass":"v1/balance","id":142438,"amount":0,"mode":"orange_ml","created_at":"2024-01-27T17:22:47.320Z","updated_at":"2024-01-27T17:22:47.320Z"},{"klass":"v1/balance","id":142437,"amount":0,"mode":"togocel","created_at":"2024-01-27T17:22:47.277Z","updated_at":"2024-01-27T17:22:47.277Z"},{"klass":"v1/balance","id":142436,"amount":0,"mode":"airtel_ne","created_at":"2024-01-27T17:22:47.237Z","updated_at":"2024-01-27T17:22:47.237Z"},{"klass":"v1/balance","id":142435,"amount":0,"mode":"free_sn","created_at":"2024-01-27T17:22:47.198Z","updated_at":"2024-01-27T17:22:47.198Z"},{"klass":"v1/balance","id":142434,"amount":0,"mode":"orange_sn","created_at":"2024-01-27T17:22:47.160Z","updated_at":"2024-01-27T17:22:47.160Z"},{"klass":"v1/balance","id":142433,"amount":0,"mode":"orange_ci","created_at":"2024-01-27T17:22:47.120Z","updated_at":"2024-01-27T17:22:47.120Z"},{"klass":"v1/balance","id":142432,"amount":0,"mode":"moov_tg","created_at":"2024-01-27T17:22:47.079Z","updated_at":"2024-01-27T17:22:47.079Z"},{"klass":"v1/balance","id":142431,"amount":0,"mode":"mtn_ci","created_at":"2024-01-27T17:22:46.960Z","updated_at":"2024-01-27T17:22:46.960Z"},{"klass":"v1/balance","id":142430,"amount":474000,"mode":"moov","created_at":"2024-01-27T17:22:46.921Z","updated_at":"2024-01-27T17:22:46.921Z"},{"klass":"v1/balance","id":142429,"amount":0,"mode":"stripe_gw","created_at":"2024-01-27T17:22:46.884Z","updated_at":"2024-01-27T17:22:46.884Z"},{"klass":"v1/balance","id":142428,"amount":0,"mode":"mtn","created_at":"2024-01-27T17:22:46.847Z","updated_at":"2024-01-27T17:22:46.847Z"}],"bank_accounts":[],"mobile_accounts":[],"card_accounts":[],"currencies":[{"klass":"v1/currency","id":1,"name":"FCFA","iso":"XOF","code":952,"prefix":null,"suffix":"CFA","div":1,"default":true,"created_at":"2018-05-27T21:26:23.618Z","updated_at":"2023-04-25T13:45:49.805Z","modes":["mtn","cybersource","moov","mtn_ci","moov_tg","orange_ci","orange_sn","free_sn","airtel_ne","togocel","orange_ml","mtn_open","mtn_ecw","ecobank_tpe","orabank_tpe","uba","stripe_gw","uba_atm","bmo","mtn_open_ci","sbin"]}]}}'
def test_webhook():
    Webhook().construct_event(
        payload=payload, 
        signature_header='t=1708343420,s=465fa77751811cd106b94f71ab5f0663503cd4aac97a95fb21ac044caf41ce0a', 
        secret='wh_sandbox_3tzRiyUcHVyEXG4dY7b6TnxZ', 
        tolerance=300)