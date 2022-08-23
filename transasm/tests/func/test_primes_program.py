import unittest

from transasm import transform

from . import primes_data


class TestPrimesProgram(unittest.TestCase):
    def test_primes_x86_program(self) -> None:
        code = primes_data.primes_x86
        updated = transform.transform(bytes(code))
        self.assertNotEqual(code, updated)
        self.assertEqual(updated, bytes(primes_data.primes_x86_transformed))

    def test_prime_x86_64_program(self) -> None:
        code = primes_data.primes_x86_64
        updated = transform.transform(bytes(code))
        self.assertNotEqual(code, updated)
