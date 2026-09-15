import hashlib
import os

# 'lab_data.txt' sits in the same folder as this script. Building the path from
# __file__ makes the script find it no matter which folder you run it from -
# running it from the repo root is what caused the "file not found" error.
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab_data.txt")

# PART 1: GENERATING THE HASH FOR THE FILE

# 1. Open the text file in 'rb' (read binary) mode.
# Reading in binary means the data is already in bytes, which SHA-256 requires.
my_file = open(DATA_FILE, "rb")

# 2. Read all the data inside the file into a variable
file_data = my_file.read()

# 3. Close the file after reading (good practice)
my_file.close()

# 4. Pass the raw file data into the SHA-256 function
my_hash_object = hashlib.sha256(file_data)

# 5. Extract the final hash string in hexadecimal format
original_file_hash = my_hash_object.hexdigest()

print("The SHA-256 hash of 'lab_data.txt' is:")
print(original_file_hash)
print("-----------------------------------------------------------------------------------")


# PART 2: VERIFYING THE FILE (Integrity Check)
# In cybersecurity, we verify a file by comparing its current hash against a trusted hash.

# 1. Ask the user to provide the trusted hash (copy and paste the one printed above)
trusted_hash = input("Paste the hash here to verify the file's integrity: ")

# 2. Read and hash the file one more time to check its CURRENT state
check_file = open(DATA_FILE, "rb")
current_data = check_file.read()
check_file.close()

# 3. Generate the hash of the file as it exists right now
current_hash = hashlib.sha256(current_data).hexdigest()

# 4. Compare the trusted hash with the file's current hash
if trusted_hash == current_hash:
    print("Success! The hashes match. The file has NOT been tampered with.")
else:
    print("Alert! The hashes do NOT match. The file has been modified.")
