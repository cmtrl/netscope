"""The local fixture should start without system or external DNS."""

import unittest
from unittest.mock import patch

from netscope.demo import DemoHandler, DemoServer


class DemoTests(unittest.TestCase):
    def test_startup_does_not_perform_reverse_dns(self):
        with patch("socket.getfqdn", side_effect=AssertionError("unexpected reverse DNS")):
            with DemoServer(("127.0.0.1", 0), DemoHandler) as server:
                self.assertEqual(server.server_name, "localhost")
                self.assertGreater(server.server_port, 0)
                self.assertEqual(server.server_address[0], "127.0.0.1")
