import time
import statistics

SECRET_PASSWORD = "PASSWORD"

def vulnerable_check(attempt):
    # this is vulnerable bc it returns false when it finds a mismatch
    if (len(attempt) != len(SECRET_PASSWORD)):
        return False
    for i in range(len(SECRET_PASSWORD)):
        if (attempt[i] != SECRET_PASSWORD[i]):
            return False # this is the problem (the leak) because it returns faster on early mismatches
    return True

def constant_time_check(attempt):
    # this is more secure bc it compares every character even if it reaches a mismatch
    if len(attempt) != len(SECRET_PASSWORD):
        return False
    result = 0
    for i in range(len(SECRET_PASSWORD)):
        # ord() takes a single unicode character as an argument and returns its corresponding integer unicode code point
        # so this is gonna capture if there's any differences:
        result |= (ord(attempt[i]) ^ ord(SECRET_PASSWORD[i]))
    return (result == 0)
