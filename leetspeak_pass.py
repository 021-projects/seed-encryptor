import random
import hashlib
import argparse

LEETSPEAK = {
    # Latin alphabet
    'a': '@', 'b': '8', 'c': '(', 'd': '|)', 'e': '3', 'f': '#', 'g': '9', 'h': '#', 'i': '1',
    'j': ';', 'k': '|<', 'l': '1', 'm': 'M', 'n': '^', 'o': '0', 'p': '|*', 'q': '9', 'r': '2',
    's': '$', 't': '7', 'u': '^', 'v': '\\/', 'w': 'vv', 'x': '><', 'y': 'Y', 'z': '2',

    # Cyrillic alphabet
    'а': '@', 'б': '8', 'в': 'B', 'г': 'r', 'д': '4', 'е': '3', 'ё': 'e', 'ж': '%', 'з': '3',
    'и': '1', 'й': '9', 'к': '|<', 'л': 'L', 'м': 'M', 'н': 'H', 'о': '0', 'п': '|*', 'р': 'P',
    'с': '$', 'т': '7', 'у': '^', 'ф': 'f', 'х': 'X', 'ц': 'u', 'ч': '4', 'ш': 'w', 'щ': 'w',
    'ы': 'y', 'э': 'e', 'ю': 'u', 'я': 'r',

    # Greek alphabet
    'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ζ': 'z', 'η': 'h', 'θ': '8', 'ι': 'i',
    'κ': 'k', 'λ': 'l', 'μ': 'm', 'ν': 'n', 'ξ': 'x', 'ο': '0', 'π': 'p', 'ρ': 'p', 'σ': '$',
    'τ': 't', 'υ': 'y', 'φ': 'f', 'χ': 'x', 'ψ': 'y', 'ω': 'w',

    # Arabic numbers and symbols
    '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'h', '5': 's', '6': 'b', '7': 't', '8': 'g',
    '9': 'q', '!': 'i', '@': 'a', '#': '$', '$': 's', '%': '5', '^': '7', '&': '8', '*': '0',

    # Additional symbols
    '-': '=', '_': '-', '=': '+', '+': '^', '{': '[', '}': ']', '[': '(', ']': ')',
    '(': '<', ')': '>', '<': '!', '>': '@', ':': ';', ';': ':', '"': "'", "'": '"', '/': '\\', '\\': '/',
    '.': ',', ',': '.', '?': '!', '¡': '1', '¿': '2'
}


# Function to convert a word into Leetspeak (supporting multiple languages)
def to_leetspeak(word):
    return ''.join([LEETSPEAK.get(c.lower(), c) for c in word])


# Function to generate a deterministic "seed" from input words
def generate_seed(words):
    # Create a deterministic string from words and hash it
    combined_words = ' '.join(words)
    return hashlib.sha256(combined_words.encode()).hexdigest()


# Function to generate a password based on deterministic "seed"
def generate_password(words, special_characters, min_length=12):
    # Generate a deterministic seed from words
    seed = generate_seed(words)

    # Use the seed for both Leetspeak conversion and character selection
    random.seed(seed)  # Ensures deterministic results

    # Convert each word to Leetspeak
    leets_words = [to_leetspeak(word) for word in words]

    # Randomly choose a special separator between words using the seed
    password_parts = []
    for word in leets_words:
        password_parts.append(word)
        password_parts.append(random.choice(special_characters))

    # Join the password parts into a single string and ensure it's at least `min_length` characters long
    password = ''.join(password_parts).rstrip(random.choice(special_characters))

    # Ensure the password meets the minimum length requirement
    while len(password) < min_length:
        password += random.choice(special_characters) + random.choice(words)

    return password


# Main function to handle the CLI arguments
def main():
    parser = argparse.ArgumentParser(description="Generate a strong password based on words and Leetspeak.")
    parser.add_argument('words', nargs='+', help="List of words to use for password generation")
    parser.add_argument('--specials', default='!@#$%^&*-_', help="Special characters to use for separating words")
    parser.add_argument('--min-length', type=int, default=12, help="Minimum password length")

    args = parser.parse_args()

    # Get the list of words and special characters
    words = args.words
    special_characters = list(args.specials)

    # Generate password
    password = generate_password(words, special_characters, args.min_length)
    print(f"Generated password: {password}")


if __name__ == "__main__":
    main()
