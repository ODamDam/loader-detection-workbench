"""Small text escaping helpers; untrusted values never introduce new lines."""

import string
import unicodedata


def single_line(value: str) -> str:
    return "".join(
        " "
        if character.isspace() or unicodedata.category(character).startswith("C")
        else character
        for character in value
    )


def markdown_text(value: str) -> str:
    # Encode HTML metacharacters; backslash-escape remaining ASCII punctuation.
    # Escaping '&' also prevents user-supplied character entities being interpreted.
    html = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}
    return "".join(
        html[character]
        if character in html
        else "\\" + character
        if character in string.punctuation
        else character
        for character in single_line(value)
    )
