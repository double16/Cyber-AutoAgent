import asyncio
import unittest

from modules.tools.web_search import web_search


class WebSearchTest(unittest.TestCase):
    def test_ddg_python3(self):
        result = asyncio.run(web_search("python3 features"))
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0, "no results")
        self.assertTrue("python" in result[0]["snippet"].lower(), "python3 not in results: " + result[0]["snippet"])
