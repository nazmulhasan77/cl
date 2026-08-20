"""
CSE-4232P Cryptography and Network Security Lab
Problem 7: Robin-Miller / Miller-Rabin Primality Test

Problem:
Use the Robin-Miller algorithm to check whether a given number P is
prime or not.

The standard name is Miller-Rabin Primality Test.
"""

import random


def miller_rabin(n, trials=10):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 = 2^s * d, where d is odd.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(trials):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


if __name__ == "__main__":
    p = int(input("Enter number P: "))
    trials = int(input("Enter number of trials (example 10): "))

    if miller_rabin(p, trials):
        print(p, "is probably prime.")
    else:
        print(p, "is composite.")
