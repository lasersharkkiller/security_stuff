# -*- coding: utf-8 -*-
import itertools

# Physical keyboard layout rows
rows = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
]

# Shifted key map
shift_map = {
    '`': '~', '1': '!', '2': '@', '3': '#', '4': '$',
    '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
    '-': '_', '=': '+', '[': '{', ']': '}', '\\': '|',
    ';': ':', "'": '"', ',': '<', '.': '>', '/': '?'
}
for c in 'abcdefghijklmnopqrstuvwxyz':
    shift_map[c] = c.upper()

# Common suffixes to try
common_suffixes = ["123", "2024", "!", "!23", "@", "1!", "321"]

def generate_walks(line, min_len=3, max_len=16):
    walks = set()
    for length in range(min_len, min(max_len, len(line)) + 1):
        for i in range(len(line) - length + 1):
            chunk = line[i:i+length]
            walks.add(chunk)
            walks.add(''.join(shift_map.get(c, c) for c in chunk))
    return walks

def combine_adjacent(lines):
    combos = []
    for i in range(len(lines) - 1):
        combos.append(lines[i] + lines[i + 1])
    return combos

def get_columns(rows):
    max_len = max(len(r) for r in rows)
    columns = []
    for i in range(max_len):
        col = ''.join(r[i] for r in rows if i < len(r))
        columns.append(col)
    return columns

def generate_diagonals():
    diagonals = set()
    # Diagonals like q-a-z, w-s-x, etc.
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

def append_suffixes(patterns):
    with_suffix = set()
    for word in patterns:
        with_suffix.add(word)
        for suffix in common_suffixes:
            with_suffix.add(word + suffix)
    return with_suffix

def all_patterns():
    walks = set()

    # Basic rows and reversed
    for row in rows:
        walks.update(generate_walks(row))
        walks.update(generate_walks(row[::-1]))

    # Row combos
    for combo in combine_adjacent(rows):
        walks.update(generate_walks(combo))
        walks.update(generate_walks(combo[::-1]))

    # Columns
    columns = get_columns(rows)
    for col in columns:
        walks.update(generate_walks(col))
        walks.update(generate_walks(col[::-1]))

    # Column combos
    for combo in combine_adjacent(columns):
        walks.update(generate_walks(combo))
        walks.update(generate_walks(combo[::-1]))

    # Diagonals
    walks.update(generate_diagonals())

    # Append common suffixes
    return append_suffixes(walks)

if __name__ == "__main__":
    patterns = all_patterns()
    with open("keyboard_walks.txt", "w") as f:
        for p in sorted(patterns):
            f.write(p + "\n")
    print(f"Generated {len(patterns)} keyboard walk patterns → keyboard_walks.txt")
