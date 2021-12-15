import random

from pypass.params import *
from pypass.consts import *

# Password generator
ALPHABET_LOWER = 'abcdefghijklmnopqrstuvwxyz'
ALPHABET_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
NUMBERS = '0123456789'
SPECIAL_CHARS = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

# Generate random integer in range start ~ (end - 1)
def generate_random_int(start, end):
    return int(random.random() * (end - start) + start)

# Probability of each type of character appearing 
# in a randomly generated password
PARAM_PWGEN_PROB_ALPHABET_LOWER = generate_random_int(20, 30)
PARAM_PWGEN_PROB_ALPHABET_UPPER = generate_random_int(20, 30)
PARAM_PWGEN_PROB_NUMBER = generate_random_int(20, 30)
PARAM_PWGEN_PROB_SPECIAL_CHARS = 100 - (PARAM_PWGEN_PROB_ALPHABET_LOWER + PARAM_PWGEN_PROB_ALPHABET_UPPER + PARAM_PWGEN_PROB_NUMBER)

# Length upper/lower limits for randomly generated password
PARAM_PWGEN_MAX_LENGTH = 25
PARAM_PWGEN_MIN_LENGTH = 15

# For user-generated passwords, lower bound for the passwor length
PARAM_STRONG_PW_MIN_LEN = 6

# Same character cannot appear more than N times in a row
PARAM_STRONG_PW_MAX_CONS = 4

# At least N alphabet lower/upper, number, special char
# must be used for a strong password
PARAM_STRONG_PW_ALPHABET_UPPER_MIN_CNT = 1
PARAM_STRONG_PW_ALPHABET_LOWER_MIN_CNT = 1
PARAM_STRONG_PW_NUMBER_MIN_CNT = 1
PARAM_STRONG_PW_SPECIAL_CHARS_MIN_CNT = 1

# Randomly select one element from an iterable or string
def select_one_random(iter):
    return iter[generate_random_int(0, len(iter))]

# Maximum value of the number of times the same character appears in a row in a given string
def max_consecutive_same_characters(text:str)->int:
    max_consecutive = 0
    current_consecutive = 0
    previous_ch = ''
    for current_ch in text:
        if previous_ch and previous_ch == current_ch:
            current_consecutive += 1
        else:
            if current_consecutive > max_consecutive:
                max_consecutive = current_consecutive
            current_consecutive = 1
        previous_ch = current_ch
    return max_consecutive

# Generates strong new password
def generate_random_pw():
    generated_pw = ''
    # Randomly determine length of new password
    pw_len = generate_random_int(PARAM_PWGEN_MIN_LENGTH, PARAM_PWGEN_MAX_LENGTH)

    # Randomly generate each character
    for i in range(pw_len):
        next_chr_type = generate_random_int(0, 100)
        next_chr = ''
        
        # Next character is lowercase alphabet
        if 0 <= next_chr_type < PARAM_PWGEN_PROB_ALPHABET_LOWER:
            next_chr = select_one_random(ALPHABET_LOWER)
        else:
            next_chr_type -= PARAM_PWGEN_PROB_ALPHABET_LOWER
        
        # Next character is uppercase alphabet
        if not next_chr and 0 <= next_chr_type < PARAM_PWGEN_PROB_ALPHABET_UPPER:
            next_chr = select_one_random(ALPHABET_UPPER)
        else:
            next_chr_type -= PARAM_PWGEN_PROB_ALPHABET_UPPER
        
        # Next character is a number
        if not next_chr and 0 <= next_chr_type < PARAM_PWGEN_PROB_NUMBER:
            next_chr = select_one_random(NUMBERS)
        else:
            next_chr_type -= PARAM_PWGEN_PROB_NUMBER
        
        # Next character is a special character
        if not next_chr and 0 <= next_chr_type < PARAM_PWGEN_PROB_SPECIAL_CHARS:
            next_chr = select_one_random(SPECIAL_CHARS)
        
        # Append selected character to the generated password
        generated_pw += next_chr
        
    return generated_pw

# Check if password is strong
def is_password_strong(pw:str)->bool:
    # If password is shorter than 6 characters
    if len(pw) < 6:
        return False
    
    # If the same character appears more than 3 times in a row
    if max_consecutive_same_characters(pw) > 3:
        return False
    
    # Contains alphabet(upper/lower), number AND special char
    # type_cnt: upper, lower, number, specialchars
    type_cnt = [0, 0, 0, 0]
    for ch in pw:
        if ch in ALPHABET_UPPER:
            type_cnt[0] += 1
        elif ch in ALPHABET_LOWER:
            type_cnt[1] += 1
        elif ch in NUMBERS:
            type_cnt[2] += 1
        else:
            type_cnt[3] += 1
    if min(type_cnt) < 1:
        return False

    return True

# Generate strong random password
def generate_strong_random_pw():
    gen = generate_random_pw()
    while not is_password_strong(gen):
        gen = generate_random_pw()
    return gen