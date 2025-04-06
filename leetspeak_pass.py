import random
import hashlib
import argparse
import getpass

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


def to_leetspeak(word):
    return ''.join([LEETSPEAK.get(c.lower(), c) for c in word])


def generate_seed(words):
    combined_words = ' '.join(words)
    return hashlib.sha256(combined_words.encode()).hexdigest()


def generate_password(words, special_characters, min_length=12):
    seed = generate_seed(words)
    random.seed(seed)
    leets_words = [to_leetspeak(word) for word in words]

    password_parts = []
    for word in leets_words:
        password_parts.append(word)
        password_parts.append(random.choice(special_characters))

    password = ''.join(password_parts).rstrip(random.choice(special_characters))

    while len(password) < min_length:
        password += random.choice(special_characters) + random.choice(words)

    return password


def prompt_words(confirm=True):
    while True:
        print("\nEnter your secret words one by one (input hidden). Press Enter on an empty line to finish.")
        words = []
        while True:
            word = getpass.getpass(prompt=f"Word {len(words) + 1}: ")
            if not word:
                break
            words.append(word)

        if not words:
            print("No words entered. Try again.")
            continue

        if not confirm:
            return words

        print("\nPlease re-enter the words to confirm:")
        confirm_words = []
        for i in range(len(words)):
            confirm_input = getpass.getpass(prompt=f"Word {i + 1}: ")
            confirm_words.append(confirm_input)

        if words == confirm_words:
            print("Words confirmed.")
            return words
        else:
            print("Words do not match. Let's try again.")


def main():
    parser = argparse.ArgumentParser(description="Generate a strong password based on words and Leetspeak.")
    parser.add_argument('--specials', default='!@#$%^&*-_', help="Special characters to use for separating words")
    parser.add_argument('--min-length', type=int, default=12, help="Minimum password length")
    parser.add_argument('--no-confirm', action='store_true', help="Skip confirmation step for words")
    args = parser.parse_args()

    words = prompt_words(confirm=not args.no_confirm)
    special_characters = list(args.specials)
    password = generate_password(words, special_characters, args.min_length)
    print(f"\nGenerated password: {password}")


if __name__ == "__main__":
    main()
