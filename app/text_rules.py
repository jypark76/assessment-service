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
