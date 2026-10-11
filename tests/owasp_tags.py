# In plain English: the rules for the OWASP tag that marks which tests prove which weaknesses.
#
# A test can carry one or more tags like @pytest.mark.owasp("A05", 89, 74). The first value is the
# OWASP Top 10:2025 category (A01 to A10) and the rest are CWE numbers the test helps prove are
# stopped. The pipeline reads these tags to show which guardrails are covered, so a typo in a tag
# must stop the run: a wrong tag would show a guardrail as covered when it is not.
import re

CATEGORY_PATTERN = re.compile(r"A(0[1-9]|10)")


# In plain English: checks the values of one tag and raises a ValueError that says what is wrong.
# A good tag has a category such as "A05" followed by at least one whole CWE number above zero, with
# no number repeated.
def check_owasp_args(args):
    if len(args) < 2:
        raise ValueError(f"an owasp tag needs a category and at least one CWE number, got {args!r}")
    category, numbers = args[0], args[1:]
    if not isinstance(category, str) or not CATEGORY_PATTERN.fullmatch(category):
        raise ValueError(f"the first value of an owasp tag must be a category from A01 to A10, got {category!r}")
    for number in numbers:
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise ValueError(f"CWE numbers in an owasp tag must be whole numbers above zero, got {number!r}")
    if len(set(numbers)) != len(numbers):
        raise ValueError(f"an owasp tag repeats a CWE number: {args!r}")


# In plain English: looks at every collected test and stops the whole run, naming the test, if any of
# its owasp tags is malformed. A tag may not carry keyword values, because the report reads only the
# positional ones.
def check_items(items):
    for item in items:
        for mark in item.iter_markers("owasp"):
            if mark.kwargs:
                raise ValueError(f"{item.nodeid}: an owasp tag takes no keyword values, got {mark.kwargs!r}")
            try:
                check_owasp_args(mark.args)
            except ValueError as problem:
                raise ValueError(f"{item.nodeid}: {problem}") from None
