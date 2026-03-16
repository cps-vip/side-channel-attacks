import time
import statistics
from password_checkers import vulnerable_check, constant_time_check

# author - Piper

def measure(func, guess, iterations=100000):
    #func is the function to check, which is vulnerable_check or constant_time_check
    # guess is password attempt we want to measure
    # iterations is number of times to repeat the measurement. it is repeated many times bc a single timing measurement is noisy and unreliable
    times = [] # store how long each individual run takes in nanoseconds
    for i in range(iterations): # repeat test over and over
        start = time.perf_counter_ns() # get current time in nanoseconds. start timestamp
        func(guess) # password checking function, which we're measuring. dont print in order to not ruin timing accuracy
        end = time.perf_counter_ns()
        times.append(end - start) # store duration for one execution
    return statistics.median(times) #return median in case of outliers

# now actually run the experiment:
# measure a guess that fails at the first character:
time_wrong = measure(vulnerable_check, "PXXXXXXX") # mismatch immediately so function exits on first loop

time_almost = measure(vulnerable_check, "PASSWORX")

not_vulnerable_wrong =  measure(constant_time_check, "PXXXXXXX")
not_vulnerable_almost =  measure(constant_time_check, "PASSWORX")


print(f"first show how many extra nanoseconds spent checking characters in vulnerable")
print(f"Median time (First char mismatch): {time_wrong} ns")
print(f"Median time (Last char mismatch):  {time_almost} ns")
print(f"Difference: {time_almost - time_wrong} ns")

print(f"now print non vulnerable")
print(f"Median time (First char mismatch): {not_vulnerable_wrong} ns")
print(f"Median time (Last char mismatch):  {not_vulnerable_almost} ns")
print(f"Difference: {not_vulnerable_almost - not_vulnerable_wrong} ns")