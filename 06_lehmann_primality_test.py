"""
CSE-4232P Cryptography and Network Security Lab
Problem 6: Lehmann Primality Test

Problem:
Use the Lehmann algorithm to check whether a given number P is prime
or not.

The Lehmann test is probabilistic. If it says COMPOSITE, the number is
certainly composite. If it passes all trials, it is probably prime.
"""

import random


def lehmann_test(p, trials=10):
    if p < 2:
        return False
    if p in (2, 3):
        return True
    if p % 2 == 0:
        return False

    for _ in range(trials):
        a = random.randint(2, p - 2)
        r = pow(a, (p - 1) // 2, p)

        # For a probable prime, result should be 1 or -1 mod p.
        if r != 1 and r != p - 1:
            return False

    return True


if __name__ == "__main__":
    p = int(input("Enter number P: "))
    trials = int(input("Enter number of trials (example 10): "))

    if lehmann_test(p, trials):
        print(p, "is probably prime.")
    else:
        print(p, "is composite.")
