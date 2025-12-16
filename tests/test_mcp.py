import unittest

from modules.tools.mcp import shorten_description


class ShortenEnglishTests(unittest.TestCase):
    def test_returns_original_when_shorter_than_max_len(self):
        text = "Short text."
        result = shorten_description(text, 50)
        self.assertEqual(result, text)

    def test_cuts_at_sentence_boundary_before_max_len(self):
        text = (
            "This is a long paragraph of English text. "
            "It contains several sentences. "
            "We want to shorten it cleanly without breaking sentences if possible!"
        )
        result = shorten_description(text, 60)
        # Should end on a sentence terminator before the limit
        self.assertTrue(result.endswith("."))
        self.assertIn("This is a long paragraph of English text.", result)
        self.assertNotIn("It contains several sentences.", result)

    def test_falls_back_to_word_boundary_when_no_sentence_terminator(self):
        text = "This is a sentence without punctuation at the end and it is quite long"
        result = shorten_description(text, 35)
        # Should not exceed max_len
        self.assertLessEqual(len(result), 35)
        # Should end on a space boundary, not in the middle of a word
        self.assertTrue(result[-1].isalpha())
        self.assertTrue(result.endswith("sentence") or result.endswith("without"))

    def test_hard_cut_when_no_spaces(self):
        text = "averyverylongwordwithnospaces"
        result = shorten_description(text, 10)
        self.assertEqual(result, text[:10])

    def test_exact_length_returns_original(self):
        text = "Exactly twenty-five chars."
        max_len = len(text)
        result = shorten_description(text, max_len)
        self.assertEqual(result, text)

    def test_leading_and_trailing_whitespace_trimmed(self):
        text = "   This is a test sentence.   "
        result = shorten_description(text, 50)
        self.assertEqual(result, "This is a test sentence.")

    def test_small_max_len(self):
        text = "Hello world."
        result = shorten_description(text, 3)
        self.assertEqual(result, "Hel")


if __name__ == "__main__":
    unittest.main()
