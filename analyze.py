import json
from collections import Counter

certificate_data = json.loads(open('public_key_comparison_results.json').read())

num_of_duplicated_pk = len(certificate_data)
print("\t\t-----Analysis Results-----")
print("\nThere are {} duplicated public keys in the data set.\n".format(num_of_duplicated_pk))

duplication_frequencies = {key: len(value) for key, value in certificate_data.items()}
occurence_counter = Counter(list(duplication_frequencies.values()))
for key in occurence_counter:
    print("{} of these public keys occurred in {} different certificates".format(occurence_counter[key], key))
print("\n")

most_duplicated = max(duplication_frequencies.items(), key = lambda x: x[1])

ca_set_of_most_revoked = set(value["CaName"] for value in certificate_data[most_duplicated[0]])
subject_set_of_most_revoked = set(value["SubjectName"] for value in certificate_data[most_duplicated[0]])

num_of_keys_used_by_different_ca = 0
num_of_keys_used_by_different_subject = 0
num_of_keys_used_by_different_subject_and_different_ca = 0
for result in certificate_data.values():
    ca_set = set(value["CaName"] for value in result)
    if len(ca_set) > 1:
        num_of_keys_used_by_different_ca += 1

    subject_set = set(value["SubjectName"] for value in result)
    if len(subject_set) > 1:
        num_of_keys_used_by_different_subject += 1

    if len(subject_set) > 1 and len(ca_set) > 1:
        num_of_keys_used_by_different_subject_and_different_ca += 1

print(num_of_keys_used_by_different_ca,  "public keys have more than one issuer")
print(num_of_keys_used_by_different_subject, "public keys have more than one subject")
print(num_of_keys_used_by_different_subject_and_different_ca, "public keys have more than one subject and more than one issuer at the same time\n")

total_num_of_good = 0
total_num_of_unknown = 0
total_num_of_revoked = 0
num_of_good_keys = 0
for key, value in certificate_data.items():
    num_of_good = 0
    num_of_revoked = 0
    num_of_unknown = 0

    for result in value:
        status = result["RevocationStatus"]
        if status == "Good":
            total_num_of_good += 1
            num_of_good += 1
        elif status == "Revoked":
            total_num_of_revoked += 1
            num_of_revoked += 1
        elif status == "Unknown":
            total_num_of_unknown += 1
            num_of_unknown += 1

    if num_of_good != len(value):
        print("{} number of total certificates".format(key), len(value))
        print("{} number of good certificates:".format(key), num_of_good)
        print("{} number of revoked certificates:".format(key), num_of_revoked)
        print("{} number of unknown certificates:".format(key), num_of_unknown)
        print("\n")
    else:
        num_of_good_keys += 1

print("Total number of good certificates:", total_num_of_good)
print("Total number of revoked certificates:", total_num_of_revoked)
print("Total number of unknown certificates:", total_num_of_unknown)
print("Number of good keys:", num_of_good_keys)

keys_shared_between_cas = []
ca_frequency_list = []
for key, value in certificate_data.items():
    ca_set = set(map(lambda result: result["CaName"], value))
    ca_set = set(map(lambda ca_name: "Thawte" if "thawte" in ca_name.lower() else ca_name, ca_set))
    ca_set = set(map(lambda ca_name: "NetLock" if "netlock" in ca_name.lower() else ca_name, ca_set))
    if len(ca_set) > 1:
        print(key, ca_set)
        ca_frequency_list.append(frozenset(ca_set))
        keys_shared_between_cas.append(key)

print(len(keys_shared_between_cas))
print(len(ca_frequency_list))
for key, value in sorted(Counter(ca_frequency_list).items(), key=lambda x: x[1], reverse=True):
    print(key, value)