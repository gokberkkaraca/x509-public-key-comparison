import subprocess

serial_number_file = "serial_numbers.txt"
revocation_list_file = "revocation_list.txt"
crl_points_list_file = "crl_points.txt"

with open(crl_points_list_file) as file:
    crl_points = [line.rstrip('\n') for line in file]
    crl_points = set(crl_points)

for crl_point in crl_points:
    bashCommand = 'wget -O crl.der ' + crl_point
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    bashCommand = "openssl crl -inform DER -in crl.der -outform PEM -out crl.pem"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    bashCommand = "openssl crl -in crl.pem -noout -text >> revocation_list.txt"
    output = subprocess.check_output(['bash', '-c', bashCommand])

with open(serial_number_file) as file:
    suspicious_serial_numbers = [line.rstrip('\n') for line in file]

with open(revocation_list_file) as file:
    revoced_serial_numbers = [line.rstrip('\n') for line in file]
    revoced_serial_numbers = [serial_number.split(" ")[6] for serial_number in revoced_serial_numbers if "Serial Number: " in serial_number]

for serial_number in suspicious_serial_numbers:
    result = (serial_number.upper() in list(map(lambda item: item.upper(), revoced_serial_numbers)))
    if result:
        print("Found revoked certificate: ", serial_number)