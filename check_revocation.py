import json
import urllib.request
import subprocess

certificate_data = json.loads(open('public_key_comparison_results.json').read())

def perform_crl_check(certificate):
    return ("CRL")

def perform_ocsp_check(certificate):
    # Get certificate chain
    chain_cert_url_list = certificate["IssuingCertificateURL"]
    if type(chain_cert_url_list) != list or len(chain_cert_url_list) <= 0:
        return "Unknown"

    if len(chain_cert_url_list) > 1:
        print("Warning: More than one chain cert.", certificate["FileName"])
        return "Unknown" # TODO
    for chain_cert_url in chain_cert_url_list:
        urllib.request.urlretrieve(chain_cert_url, "chain.crt")
        completed_process = subprocess.run("openssl x509 -in chain.crt -inform DER -out chain.pem -outform PEM".split())
        if completed_process.returncode != 0:
            return "Unknown" # TODO

    # Generate OCSP request
    ocsp_url = certificate["OCSP"][0]
    ocsp_process = subprocess.run(("openssl ocsp -issuer chain.pem -cert certificates/" + certificate["FileName"] + " -text -url " + ocsp_url).split(), text=True, capture_output=True)
    results = [line for line in (ocsp_process.stdout).splitlines() if certificate["FileName"] in line]
    if len(results) == 1:
        return (results[0].split(' ')[1]).capitalize()

for public_key, certificate_set in certificate_data.items():
    total_num_of_certificates = len(certificate_set)
    num_of_revoced_certificates = 0
    num_of_unknown_certificates = 0
    for certificate in certificate_set:
        revocation_status = "Unknown"
        is_ocsp_available = type(certificate["OCSP"]) == list and len(certificate["OCSP"]) > 0
        is_crl_available = type(certificate["CrlPoints"]) == list and len(certificate["CrlPoints"]) > 0
        if not(is_crl_available) and not(is_ocsp_available):
            continue
        else:
            if is_ocsp_available:
                revocation_status = perform_ocsp_check(certificate)
            else:
                perform_crl_check(certificate)
        certificate["RevocationStatus"] = revocation_status
        print(revocation_status)