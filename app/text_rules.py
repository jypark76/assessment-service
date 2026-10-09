# In plain English: rules about text that every route shares, kept in one place so a
# new route cannot forget them.


# In plain English: refuses text the database cannot store. A null character (the
# invisible character with code zero) makes the database driver fail, and that would
# come back as a plain 500 that a client may retry forever. Rejecting it here turns it
# into a proper 422 "bad input". Text that cannot be written out as UTF-8 (for example
# half of a character pair) is refused for the same reason. The messages are fixed
# wording and never quote the text.
def must_be_storable_text(value):
    if "\x00" in value:
        raise ValueError("Text must not contain null characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Text must be valid Unicode") from None
    return value


# In plain English: first checks the text can be stored at all, then trims the spaces at
# either end and checks the length. The wording of each refusal is fixed and never quotes
# what the caller sent.
def trimmed(value, longest):
    value = must_be_storable_text(value).strip()
    if not 1 <= len(value) <= longest:
        raise ValueError(f"Must be 1 to {longest} characters after trimming spaces")
    return value
