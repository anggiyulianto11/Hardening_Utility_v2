from ui.v1_theme import V1ThemeManager


def test_theme_choices_match_v1():
    assert V1ThemeManager.THEMES == ("System", "Dark", "Light")
