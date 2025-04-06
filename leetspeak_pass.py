import random
import hashlib
import argparse

# Leetspeak conversion dictionary
LEETSPEAK = {
    'a': '@', 'b': '8', 'c': '(', 'd': '|)', 'e': '3', 'f': '#', 'g': '9', 'h': '#', 'i': '1',
    'j': ';', 'k': '|<', 'l': '1', 'm': 'M', 'n': '^', 'o': '0', 'p': '|*', 'q': '9', 'r': '2',
    's': '$', 't': '7', 'u': '^', 'v': '\\/', 'w': 'vv', 'x': '><', 'y': 'Y', 'z': '2'
}


# Function to convert a word into Leetspeak
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
