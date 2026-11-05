import pytest

from app.services.username_suggestions import generate_username_candidates


@pytest.mark.parametrize(
    ("display_name", "expected"),
    [
        ("Isaack Gitau", "isaack_gitau"),
        ("  Isaack   Gitau  ", "isaack_gitau"),
        ("\u00c9lodie Martin", "elodie_martin"),
        ("123 Isaack", "user_123_isaack"),
        ("Isaack!Gitau", "isaack_gitau"),
        ("Isaack-Gitau", "isaack_gitau"),
    ],
)
def test_candidate_generation_normalizes_display_name(
    display_name: str,
    expected: str,
) -> None:
    candidates = generate_username_candidates(display_name)

    assert candidates[0] == expected


def test_candidate_generation_includes_separatorless_variant() -> None:
    candidates = generate_username_candidates("Isaack Gitau")

    assert candidates[:2] == ["isaack_gitau", "isaackgitau"]


def test_candidate_generation_includes_numeric_suffixes() -> None:
    candidates = generate_username_candidates("Isaack Gitau")

    assert candidates[2:5] == [
        "isaack_gitau2",
        "isaack_gitau3",
        "isaack_gitau4",
    ]


def test_candidate_generation_returns_no_candidates_without_ascii_text() -> None:
    assert generate_username_candidates("??") == []


def test_candidate_generation_returns_no_candidates_for_one_character_name() -> None:
    assert generate_username_candidates("A") == []


def test_candidate_generation_obeys_username_format_and_length() -> None:
    candidates = generate_username_candidates("A very long display name " * 10)

    assert candidates
    assert all(3 <= len(candidate) <= 30 for candidate in candidates)
    assert all(candidate[0].isalpha() for candidate in candidates)
    assert all(candidate.isascii() and candidate.islower() for candidate in candidates)
    assert all("__" not in candidate for candidate in candidates)


def test_candidate_generation_deduplicates_candidates() -> None:
    candidates = generate_username_candidates("Isaack Gitau")

    assert len(candidates) == len(set(candidates))


def test_candidate_generation_handles_leading_digits_without_dropping_them() -> None:
    candidates = generate_username_candidates("123 Isaack")

    assert candidates[0] == "user_123_isaack"
    assert candidates[1] == "user123isaack"
