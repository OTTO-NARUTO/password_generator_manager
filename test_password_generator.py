import string
import unittest
from password_generator import generate_password  # Import your function

class TestPasswordGenerator(unittest.TestCase):

    def test_length(self):
        """Check if password length matches input."""
        self.assertEqual(len(generate_password(10)), 10)
        self.assertEqual(len(generate_password(20)), 20)

    def test_uppercase(self):
        """Ensure uppercase letters are included."""
        password = generate_password(12, include_upper=True, include_numbers=False, include_special=False)
        self.assertTrue(any(c.isupper() for c in password))

    def test_numbers(self):
        """Ensure numbers are included."""
        password = generate_password(12, include_upper=False, include_numbers=True, include_special=False)
        self.assertTrue(any(c.isdigit() for c in password))

    def test_special_characters(self):
        """Ensure special characters are included."""
        password = generate_password(12, include_upper=False, include_numbers=False, include_special=True)
        self.assertTrue(any(c in string.punctuation for c in password))

    def test_exclude_all(self):
        """Ensure only lowercase letters are used when all options are off."""
        password = generate_password(12, include_upper=False, include_numbers=False, include_special=False)
        self.assertTrue(all(c in string.ascii_lowercase for c in password))

    def test_zero_length(self):
        """Ensure error is raised for zero length."""
        with self.assertRaises(ValueError):
            generate_password(0)

    def test_negative_length(self):
        """Ensure error is raised for negative length."""
        with self.assertRaises(ValueError):
            generate_password(-5)

if __name__ == "__main__":
    unittest.main()
