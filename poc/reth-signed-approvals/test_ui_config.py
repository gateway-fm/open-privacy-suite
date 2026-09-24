import unittest

from ui_config import normalize_start


class UIConfigurationTest(unittest.TestCase):
    def test_adaptive_uses_configured_wallets_and_preserves_controls(self):
        request = {"pattern": "adaptive", "durationSec": 60, "numAccounts": 0,
                   "privacyMode": True, "transactionType": "erc20-approve",
                   "adaptiveInitialRate": 500, "adaptiveRateStep": 100, "adaptiveTargetPending": 5000}
        result = normalize_start(request)
        self.assertEqual(result, {**request, "numAccounts": 10})
        self.assertEqual(request["numAccounts"], 0)

    def test_configuration_errors_are_explicit(self):
        valid = {"pattern": "adaptive", "durationSec": 60, "privacyMode": True}
        for override, message in [({"numAccounts": 100}, "ten"), ({"gasless": True}, "fees"),
                                  ({"fixNonceGaps": True}, "not wired"),
                                  ({"privacyMode": False}, "Through Privacy Proxy"),
                                  ({"pattern": "adaptive-realistic"}, "individual")]:
            with self.subTest(override=override), self.assertRaisesRegex(ValueError, message):
                normalize_start({**valid, **override})


if __name__ == "__main__":
    unittest.main()
