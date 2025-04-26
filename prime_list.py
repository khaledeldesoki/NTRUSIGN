from sympy import isprime

def generate_first_n_primes(n):
    """
    Generates a list containing the first n prime numbers.

    Args:
        n (int): The number of prime numbers to generate.

    Returns:
        list: A list of the first n prime numbers. Returns an empty list if n <= 0.
    """
    if n <= 0:
        return []
    
    primes = []  # List to store prime numbers
    number = 2   # Start checking from 2 (first prime number)
    
    while len(primes) < n:
        if isprime(number):
            primes.append(number)
        number += 1
    
    return primes

