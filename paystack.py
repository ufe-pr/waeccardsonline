import os
from requests import Session, Response

class PaystackResponse():

    def __init__(self, data=None, meta=None):
        self.data = data
        self.meta = meta


class Paystack():

    
    s = Session()
    base_url = "https://api.paystack.co"

    def __init__(self, secret_key=None, callback_url=None):
        self.callback_url=callback_url
        if secret_key:
            self._secret_key = secret_key
        else:
            self._secret_key = os.getenv("PAYSTACK_SECRET_KEY")

        if not self._secret_key:
            raise ValueError("Please supply a valid Paystack secret key")

        self.s.headers.update({'Authorization': "Bearer %s" % self._secret_key})

    
    def _send_request(self, route="", params=None, body=None, method="POST", headers=None) -> PaystackResponse:
        request_url = None
        response: Response
        # headers = headers or dict()
        # sess_head = self.s.headers.copy()
        # sess_head.update(headers)
        # headers = sess_head
        if route:
            if not route.startswith("/"):
                route = "/" + route
            request_url = self.base_url + route
        else:
            raise ValueError("A valid route should be passed to the method")

        if method.upper() == "POST":
            if not body:
                raise ValueError("A request body has to be passed with a POST request")

            response = self.s.post(request_url, data=body, headers=headers)

        elif method.upper() == "GET":
            response = self.s.get(request_url, params=params, headers=headers)
        
        else:
            raise ValueError("Unknown HTTP method recieved")

        if 399 >= response.status_code >= 200:
            data = response.json()

            return PaystackResponse(data=data.get('data'), meta=data.get('meta'))
        else:
            response.raise_for_status()

        return PaystackResponse()

    
    def initialize(self, amount=None, email=None, currency="NGN", callback=None, reference=None, metadata=None):
        request_body = dict()

        request_body['amount'] = amount
        request_body['email'] = email
        request_body['currency'] = currency
        if callback or self.callback_url: request_body['callback_url'] = callback or self.callback_url
        if reference: request_body['reference'] = str(reference)
        if metadata: request_body['metadata'] = metadata

        pr = self._send_request("/transaction/initialize", body=request_body)

        return pr.data.get("authorization_url")

    
    def verify(self, reference):
        pr = self._send_request("/transaction/verify/%s" % reference, method="GET")
        status = pr.data.get('status') == 'success'
        if status:
            return pr.data
        return None

