import http.client
import threading
import unittest
from unittest.mock import patch

from gasstorm_compare import GasstormStack


class Connection:
    def __init__(self, timeout=False):
        self.timeout = timeout
        self.sent = False
        self.closed = False
        self.requests = 0

    def request(self, *_):
        if self.sent:
            raise http.client.CannotSendRequest("Request-sent")
        self.requests += 1
        self.sent = True

    def getresponse(self):
        if self.timeout:
            raise TimeoutError("read timed out")
        return self

    status = 200

    def read(self):
        return b'{"jsonrpc":"2.0","id":1,"result":{"pending":"0x0","queued":"0x0"}}'

    def close(self):
        self.closed = True


class RpcRecoveryTest(unittest.TestCase):
    def test_timeout_discards_connection_without_replaying_request(self):
        stack = GasstormStack.__new__(GasstormStack)
        stack.rpc_local = threading.local()
        stack.rpc_connections = []
        stack.rpc_connections_lock = threading.Lock()
        broken, healthy = Connection(timeout=True), Connection()
        with patch('gasstorm_compare.http.client.HTTPConnection', side_effect=[broken, healthy]):
            with self.assertRaises(TimeoutError):
                stack._rpc('http://127.0.0.1:1', 'eth_sendRawTransaction', ['0x01'])
            self.assertEqual(broken.requests, 1, 'ambiguous transaction submission was replayed')
            result = stack._rpc('http://127.0.0.1:1', 'txpool_status', [])
            self.assertEqual(result['result']['queued'], '0x0')
            self.assertTrue(broken.closed)
            self.assertEqual(stack.rpc_connections, [healthy])


if __name__ == '__main__':
    unittest.main()
