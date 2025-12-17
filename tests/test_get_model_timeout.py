#!/usr/bin/env python3
import unittest

from modules.config.models.factory import get_model_timeout
from strands.models.ollama import OllamaModel


class GetModelTimeoutTests(unittest.TestCase):
    @staticmethod
    def _ollama_model_with_timeout(timeout):
        if timeout:
            ollama_client_args = {
                "timeout": timeout,
            }
        else:
            ollama_client_args = None

        return OllamaModel(
            host="http://127.0.0.1:11434",
            model_id="llama3.2",
            ollama_client_args=ollama_client_args
        )

    def test_model_none_returns_default(self):
        self.assertEqual(get_model_timeout(None, default_timeout=30), 30)
        self.assertIsNone(get_model_timeout(None, default_timeout=None))

    def test_non_ollama_model_returns_default(self):
        class DummyModel:
            pass

        self.assertEqual(get_model_timeout(DummyModel(), default_timeout=45), 45)
        self.assertIsNone(get_model_timeout(DummyModel(), default_timeout=None))

    def test_ollama_model_with_timeout_in_client_args_returns_float(self):
        model = self._ollama_model_with_timeout(12.5)
        self.assertEqual(get_model_timeout(model, default_timeout=30), 12.5)

        model2 = self._ollama_model_with_timeout(20)
        self.assertEqual(get_model_timeout(model2, default_timeout=30), 20.0)

    def test_ollama_model_without_timeout_key_returns_default(self):
        model = self._ollama_model_with_timeout(None)
        self.assertEqual(get_model_timeout(model, default_timeout=30), 30)

    def test_default_timeout_falsy_values_fall_back_to_default(self):
        # model_timeout starts as default_timeout (0), which is falsy => returns default_timeout (0)
        self.assertEqual(get_model_timeout(self._ollama_model_with_timeout(0), default_timeout=0), 0)

        # default_timeout is None -> model_timeout becomes 0.0 (falsy) -> falls back to None
        self.assertIsNone(get_model_timeout(self._ollama_model_with_timeout(0), default_timeout=None))
