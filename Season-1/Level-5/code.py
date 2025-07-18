# Welcome to Secure Code Game Season-1/Level-5!

# This is the last level of our first season, good luck!

import binascii
import random
import secrets
import hashlib
import os
import bcrypt

class Random_generator:

    # generates a random token
    def generate_token(self, length=8, alphabet=(
    '0123456789'
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    )):
        return ''.join(random.choice(alphabet) for _ in range(length))

    # generates salt
    def generate_salt(self, rounds=12):
        salt = ''.join(str(random.randint(0, 9)) for _ in range(21)) + '.'
        return f'$2b${rounds}${salt}'.encode()

class SHA256_hasher:

    # produces the password hash by combining password + salt because hashing
    def password_hash(self, password, salt):
        password_hash = bcrypt.hashpw(password.encode(), salt)
        return password_hash.decode('ascii')

    # verifies that the hashed password reverses to the plain text version on verification
    def password_verification(self, password, password_hash):
        password_hash = password_hash.encode('ascii')
        return bcrypt.checkpw(password.encode(), password_hash)

class MD5_hasher:

    # Secure password hashing using bcrypt
    def password_hash(self, password):
        # Generate salt using Random_generator
        salt = Random_generator().generate_salt()
        password_hash = bcrypt.hashpw(password.encode(), salt)
        # Return the salt and hash for storage/verification
        return f"{salt.decode()}${password_hash.decode('ascii')}"

    # Secure password verification using bcrypt
    def password_verification(self, password, stored_hash):
        # Split the stored hash to get salt and password hash
        try:
            salt_str, hash_str = stored_hash.split('$', 3)[-2:]
            salt = '$'.join(stored_hash.split('$', 4)[:4]).encode()
            password_hash = hash_str.encode('ascii')
        except Exception:
            return False
        # Hash the password with the extracted salt
        computed_hash = bcrypt.hashpw(password.encode(), salt)
        # Compare the computed hash with the stored hash securely
        return secrets.compare_digest(computed_hash, password_hash)
# a collection of sensitive secrets necessary for the software to operate
PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
PUBLIC_KEY = os.environ.get('PUBLIC_KEY')
SECRET_KEY = 'TjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8'
PASSWORD_HASHER = 'MD5_hasher'


# Contribute new levels to the game in 3 simple steps!
# Read our Contribution Guideline at github.com/skills/secure-code-game/blob/main/CONTRIBUTING.md