# -*- coding: utf-8 -*-
import itertools

# Keyboard layout rows
rows = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
]

# Shifted symbols
shift_map = {
    '`': '~', '1': '!', '2': '@', '3': '#', '4': '$',
    '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
    '-': '_', '=': '+', '[': '{', ']': '}', '\\': '|',
    ';': ':', "'": '"', ',': '<', '.': '>', '/': '?'
}
for c in 'abcdefghijklmnopqrstuvwxyz':
    shift_map[c] = c.upper()

# Suffixes to append
common_suffixes = ["123", "2024", "!", "!23", "@", "1!", "321"]

# Leetspeak mapping
leet_map = {
    'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'], 's': ['5', '$'], 't': ['7'], 'l': ['1']
}

def generate_walks(line, min_len=3, max_len=16):
    walks = set()
    for length in range(min_len, min(max_len, len(line)) + 1):
        for i in range(len(line) - length + 1):
            chunk = line[i:i+length]
            walks.add(chunk)
            walks.add(''.join(shift_map.get(c, c) for c in chunk))
    return walks

def combine_adjacent(lines):
    return [lines[i] + lines[i+1] for i in range(len(lines) - 1)]

def get_columns(rows):
    max_len = max(len(r) for r in rows)
    return [''.join(r[i] for r in rows if i < len(r)) for i in range(max_len)]

def generate_diagonals():
    diagonals = set()
    map_rows = [list(r) for r in rows]
    min_row_len = min(len(r) for r in map_rows)

    for col in range(min_row_len):
        diag1 = ''.join(map_rows[i][col] for i in range(len(map_rows)) if col < len(map_rows[i]))
        diag2 = ''.join(map_rows[i][-(col + 1)] for i in range(len(map_rows)) if (-(col + 1)) >= -len(map_rows[i]))
        if len(diag1) >= 3:
            diagonals.update(generate_walks(diag1))
        if len(diag2) >= 3:
            diagonals.update(generate_walks(diag2))
    return diagonals

def apply_leetspeak(word):
    results = set([word])
    for i, c in enumerate(word):
        if c.lower() in leet_map:
            for replacement in leet_map[c.lower()]:
                for base in list(results):
                    modified = base[:i] + replacement + base[i+1:]
                    results.add(modified)
    return results

def append_suffixes_and_variants(words):
    final = set()
    for word in words:
        final.add(word)
        capitalized = word.capitalize()
        reversed_word = word[::-1]

        for suffix in common_suffixes:
            final.add(word + suffix)
            final.add(capitalized + suffix)
            final.add(reversed_word + suffix)

        # Leetspeak variants with suffixes
        for leet in apply_leetspeak(word):
            final.add(leet)
            for suffix in common_suffixes:
                final.add(leet + suffix)
    return final

def all_patterns():
    walks = set()

    # Rows
    for row in rows:
        walks.update(generate_walks(row))
        walks.update(generate_walks(row[::-1]))

    # Row combinations
    for combo in combine_adjacent(rows):
        walks.update(generate_walks(combo))
        walks.update(generate_walks(combo[::-1]))

    # Columns
    cols = get_columns(rows)
    for col in cols:
        walks.update(generate_walks(col))
        walks.update(generate_walks(col[::-1]))

    # Column combinations
    for combo in combine_adjacent(cols):
        walks.update(generate_walks(combo))
        walks.update(generate_walks(combo[::-1]))

    # Diagonals
    walks.update(generate_diagonals())

    # Apply variants
    return append_suffixes_and_variants(walks)

if __name__ == "__main__":
    patterns = all_patterns()
    with open("keyboard_walks.txt", "w") as f:
        for p in sorted(patterns):
            f.write(p + "\n")
    print(f"✅ Generated {len(patterns)} enhanced keyboard walk patterns → keyboard_walks.txt")
