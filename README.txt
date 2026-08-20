CSE-4232P Cryptography and Network Security Lab Solutions
B.Sc. Engg. Part 4, Even Semester, Session 2020-2021, Examination 2024

Files:
01_caesar_cipher.py
02_polygram_substitution_hill_cipher.py
03_transposition_cipher.py
04_double_transposition_cipher.py
05_one_time_pad.py
06_lehmann_primality_test.py
07_miller_rabin_primality_test.py
08_md5_hash.py
09_sha_hash.py
10_rsa_encrypt_decrypt.py
11_diffie_hellman_key_exchange.py
12_pgp_authentication_and_transmission_confidentiality.py
13_pgp_authentication_and_storage_confidentiality.py
14_pgp_storage_and_authentication_confidentiality.py

Notes:
- All programs are written to be simple and easy to understand.
- Problem statements are included as comments/docstrings in every .py file.
- Problem 2 uses Hill Cipher as the polygram substitution cipher with block size 3.
- Problem 7 is written as Miller-Rabin, the standard name of the Robin-Miller test.
- Problems 12-14 are educational simulations of PGP workflow using standard Python libraries.
  Their small RSA values and XOR-based symmetric cipher are for lab demonstration only,
  not for real-world security.
- MD5 and SHA-1 are legacy hash algorithms and are included because they appear in the lab specification.

Run any program with:
python filename.py
