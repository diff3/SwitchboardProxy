import os
import tempfile
import unittest
from importlib import reload

import proxy.cli.completion_utils as completion_utils
import proxy.cli.history as history_module


class EditorFeatureTest(unittest.TestCase):
    def test_longest_common_prefix_expands_until_values_differ(self):
        self.assertEqual(
            completion_utils.longest_common_prefix(
                ["MSG_MOVE_FALL_LAND", "MSG_MOVE_HEARTBEAT"]
            ),
            "MSG_MOVE_",
        )

    def test_longest_common_prefix_returns_full_value_for_single_match(self):
        self.assertEqual(
            completion_utils.longest_common_prefix(["proxy"]),
            "proxy",
        )

    def test_history_persists_between_loads(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            history_path = os.path.join(tmpdir, "proxy_history.txt")

            history_module._HISTORY_FILE = history_module.Path(history_path)
            reload(history_module)
            history_module._HISTORY_FILE = history_module.Path(history_path)

            history_module.append_history("proxy show")
            history_module.append_history("proxy show world")

            loaded = history_module.load_history()
            self.assertEqual(loaded[-2:], ["proxy show", "proxy show world"])


if __name__ == "__main__":
    unittest.main()
