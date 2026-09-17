import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("stack", pathlib.Path(__file__).with_name("stack.py"))
stack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stack)


class OwnershipTests(unittest.TestCase):
    def test_shutdown_refuses_reused_pid(self):
        record = {"pid": 456, "started": "Thu Sep 17 12:00:00 2026"}
        self.assertTrue(stack.same_process(record, "Thu Sep 17 12:00:00 2026"))
        self.assertFalse(stack.same_process(record, "Thu Sep 17 13:00:00 2026"))
        self.assertFalse(stack.same_process(record, ""))

    def test_compose_is_scoped_and_ports_are_loopback(self):
        ports = {"postgres": 19001, "redis": 19002}
        doc = stack.compose_document(ports, "test-password")
        self.assertEqual(doc["services"]["postgres"]["ports"], ["127.0.0.1:19001:5432"])
        self.assertEqual(doc["services"]["redis"]["ports"], ["127.0.0.1:19002:6379"])
        for service in doc["services"].values():
            self.assertNotIn("container_name", service)
        self.assertNotIn("external", doc["volumes"]["postgres"])


if __name__ == "__main__":
    unittest.main()
