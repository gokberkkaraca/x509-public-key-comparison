import json
from collections import Counter

json_data = json.loads(open('public_key_comparison.json').read())

num_of_duplicated_pk = len(json_data)
print("There are {} duplicated public keys in the data set.\n".format(num_of_duplicated_pk))

duplication_frequencies = {key: len(value) for key, value in json_data.items()}
occurence_counter = Counter(list(duplication_frequencies.values()))
for key in occurence_counter:
    print("{} of these public keys occurred in {} different certificates".format(occurence_counter[key], key))
print("\n")

most_duplicated = max(duplication_frequencies.items(), key = lambda x: x[1])
#  print("Most duplicated key ('{}') is duplicated {} times.\n".format(most_duplicated[0], most_duplicated[1]))

ca_set_of_most_revoked = set(value["CaName"] for value in json_data[most_duplicated[0]])
print(len(ca_set_of_most_revoked))

subject_set_of_most_revoked = set(value["SubjectName"] for value in json_data[most_duplicated[0]])
print(len(subject_set_of_most_revoked))

num_of_keys_used_by_different_ca = 0
num_of_keys_used_by_different_subject = 0
num_of_keys_used_by_different_subject_and_different_ca = 0
for result in json_data.values():
    ca_set = set(value["CaName"] for value in result)
    if len(ca_set) > 1:
        num_of_keys_used_by_different_ca += 1

    subject_set = set(value["SubjectName"] for value in result)
    if len(subject_set) > 1:
        num_of_keys_used_by_different_subject += 1

    if len(subject_set) > 1 and len(ca_set) > 1:
        num_of_keys_used_by_different_subject_and_different_ca += 1

print(num_of_keys_used_by_different_ca, " public keys have more than one issuer")
print(num_of_keys_used_by_different_subject, " public keys have more than one subject")
print(num_of_keys_used_by_different_subject_and_different_ca, " public keys have more than one subject and more than one issuer at the same time")
