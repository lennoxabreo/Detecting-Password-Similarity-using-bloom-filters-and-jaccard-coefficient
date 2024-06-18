import hashlib
from bitarray import bitarray


# the initial thought process behind this class was to create a class t called config that would help us use all three beta files to crosscheck them
# however we decided to create a global variable further in the code instead since it would be more efficent. 

# class Config:
#     def __init__(self, beta1, beta2, beta3):
#         self.beta1 = beta1
#         self.beta2 = beta2
#         self.beta3 = beta3

# # Create a global variable for the newly created beta files to access them in the second stage of the code
# config = Config('Beta1.txt', 'Beta2.txt', 'Beta3.txt')

class BloomFilter:
    
#k=1
    def __init__(self, size=1000, hash_count=15):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bitarray(size)
        self.bit_array.setall(0)
        
#k=2
    def _hashes(self, item):
        hashes = []
        for i in range(self.hash_count):
            hash_fn = hashlib.sha256((str(i) + item).encode()).hexdigest()
            hashes.append(int(hash_fn, 16) % self.size)
        return hashes
#k=3
    def add(self, item):
        for hash_val in self._hashes(item):
            self.bit_array[hash_val] = 1
#k=4
    def __contains__(self, item):
        return all(self.bit_array[hash_val] for hash_val in self._hashes(item))
#k=5
def extract_passwords(filename, length, count):
    passwords = []
    with open(filename, 'r', encoding='latin1') as file:
        for line in file:
            pw = line.strip()
            if len(pw) == length:
                passwords.append(pw)
            if len(passwords) == count:
                break
    return sorted(passwords)

#k=6
def bigrams(password):
    return [password[i:i+2] for i in range(len(password) - 1)]
#k=7
def create_bloom_filter(passwords, size=1000, hash_count=15):
    bf = BloomFilter(size, hash_count)
    for password in passwords:
        for bigram in bigrams(password):
            bf.add(bigram)
    return bf
#k=8
def save_bloom_filters(filename, passwords, size=1000, hash_count=15):
    with open(filename, 'w') as file:
        for password in passwords:
            bf = generate_bloom_filter_for_password(password, size, hash_count)
            bit_array_str = ''.join(['1' if bit else '0' for bit in bf.bit_array])
            file.write(f"{password},{bit_array_str}\n")
#k=9
def generate_bloom_filter_for_password(password, size=1000, hash_count=15):
    bf = BloomFilter(size, hash_count)
    for bigram in bigrams(password):
        bf.add(bigram)
    return bf
#k=10
def jaccard_coefficient(bf1, bf2):
    intersection = (bf1.bit_array & bf2.bit_array).count()
    union = (bf1.bit_array | bf2.bit_array).count()
    return intersection / union if union != 0 else 0
#k=11
def compare_passwords(password1, password2):
    bf1 = generate_bloom_filter_for_password(password1)
    bf2 = generate_bloom_filter_for_password(password2)
    return jaccard_coefficient(bf1, bf2)
#k=12
def deg_of_similarity(password, modifications):
    bf_original = generate_bloom_filter_for_password(password)
    similarities = []
    for mod in modifications:
        bf_mod = generate_bloom_filter_for_password(mod)
        similarity = jaccard_coefficient(bf_original, bf_mod)
        similarities.append((mod, similarity))
    return similarities

# def take_owner_input():
#     filename = input("Enter the filename (rockyou.txt): ")
#     length1 = int(input("Enter the length of passwords for Dataset1 (first dataset should have 8 characters. Enter 9): "))
#     count1 = int(input("Enter the number of passwords for Dataset1 (Enter 100): "))
    
#     length2 = int(input("Enter the length of passwords for Dataset2 (second dataset should have 10 characters. Enter 11): "))
#     count2 = int(input("Enter the number of passwords for Dataset2 (Enter 100): "))
    
#     length3 = int(input("Enter the length of passwords for Dataset3 (third dataset should have 12 characters. Enter 13): "))
#     count3 = int(input("Enter the number of passwords for Dataset3 (Enter 100): "))

#     return filename, length1, count1, length2, count2, length3, count3

# if __name__ == "__main__":
#     filename, length1, count1, length2, count2, length3, count3 = take_owner_input()

#     # Extracting passwords from the rockyou.txt file into the datasets
#     dataset1 = extract_passwords(filename, length1, count1)
#     dataset2 = extract_passwords(filename, length2, count2)
#     dataset3 = extract_passwords(filename, length3, count3)

#     # using the create_bloom_filter function, we create the bloom filters for each of the datasets
#     save_bloom_filters('Beta1.txt', dataset1)
#     save_bloom_filters('Beta2.txt', dataset2)
#     save_bloom_filters('Beta3.txt', dataset3)

#     print("Files Beta1.txt, Beta2.txt, and Beta3.txt have been created with Bloom filter representations.")
    
    
#The above lines (74 - 101) have been commented out since the beta files have been created and there is no use for the function(def take_owner_input()) once the files have been created
#it takes my input to create the beta files

# k=13 creates bloom filter for inputted password to crosscheck with beta files
def produce_blooms(password):
    bf = generate_bloom_filter_for_password(password)
    bit_array_str = ''.join(['1' if bit else '0' for bit in bf.bit_array])
    return bf, bit_array_str
# k=14
def read_b_filter_from_file(filename, password):
    with open(filename, 'r') as file:
        for line in file:
            pw, b_filter = line.strip().split(',')
            if pw == password:
                bf = BloomFilter(size=len(b_filter), hash_count=15)
                bf.bit_array = bitarray(b_filter)
                return bf
    return None
# k=15
def read_all_b_filters_from_file(filename):
    b_filters = {}
    with open(filename, 'r') as file:
        for line in file:
            pw, b_filter = line.strip().split(',')
            bf = BloomFilter(size=len(b_filter), hash_count=15)
            bf.bit_array = bitarray(b_filter)
            b_filters[pw] = bf
    return b_filters

# THIS CODE ONLY TAKES IN PASSWORDS AND NOT BLOOM FILTERS
# determine_similarity
# k=16
def determine_similarity(input_password, beta_files, threshold=0.7):
    bf_input, _ = produce_blooms(input_password)  # Generate Bloom filter for input password
    results = []
    for beta_file in beta_files:
        b_filters = read_all_b_filters_from_file(beta_file)  # Read Bloom filters from beta file
        for password, bf in b_filters.items():
            similarity = jaccard_coefficient(bf_input, bf)  # Compare Bloom filters using Jaccard coefficient
            if similarity >= threshold:
                results.append((password, similarity))
    return results

# def compare_two_passwords(password1, password2):
#     bf1 = generate_bloom_filter_for_password(password1)
#     bf2 = generate_bloom_filter_for_password(password2)
#     similarity = jaccard_coefficient(bf1, bf2)
#     return similarity

# declaring globally an array of the beta files. 

beta_files = ['Beta1.txt', 'Beta2.txt', 'Beta3.txt']

password1 = input("Enter first password to be compared:")
password2 = input("Enter second password to be compared:")

similarity = compare_passwords(password1,password2)
print(f"The similarity between '{password1}' and '{password2}' is {similarity}")

similarCheck1 = determine_similarity(password1,beta_files)
similarCheck2 = determine_similarity(password2,beta_files)

if similarCheck1:
    print(f"The password '{password1}' is similar to the following passwords in the datasets:")
    for password, similarity in similarCheck1:
        print(f"Password: {password}, Similarity: {similarity}")
else:
    print(f"The password '{password1}' is not similar to any passwords in the datasets.")

if similarCheck2:
    print(f"The password '{password2}' is similar to the following passwords in the datasets.")

   