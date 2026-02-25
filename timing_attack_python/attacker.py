import time
import statistics
import string

SECRET_PASSWORD = "PASSWORD"

def vulnerable_check(attempt):
    # this is vulnerable bc it returns false when it finds a mismatch
    if (len(attempt) != len(SECRET_PASSWORD)):
        return False
    for i in range(len(SECRET_PASSWORD)):
        if (attempt[i] != SECRET_PASSWORD[i]):
            return False # this is the problem (the leak) because it returns faster on early mismatches
        time.sleep(0.0001)
    return True

def crack_password(length):
    alphabet = string.ascii_uppercase
    current_cracked_password = "" # store password guessed correctly so far
    print(f"starting attack on password with {length} characters")
    for i in range(length): # loop over each index of password
        timings = {} # dictionary to store key = character : value = timing
        for char in alphabet:
            guess = list(current_cracked_password.ljust(length, 'X'))
            #ljust() = left justify. use X as padding character. so extends current guessed password to real password length
            # make extended password string a character list
            guess[i] = char # replace w/ test character
            test_str = "".join(guess) # turn back into string
            # need to measure multiple times bc of noise:
            sample_times = []
            for j in range(5000): 
                start = time.perf_counter_ns()
                vulnerable_check(test_str)
                end = time.perf_counter_ns()
                sample_times.append(end - start)
            timings[char] = statistics.median(sample_times)
        #character that took longest is the right character
        right_char = max(timings, key=timings.get)
        current_cracked_password += right_char
        print(f"position {i} has been discovered to be {right_char} with confidence {timings[right_char]} ns")
    return current_cracked_password

if __name__ == "__main__":
    result = crack_password(len(SECRET_PASSWORD))
    print(f"the password is probably {result}")

            
