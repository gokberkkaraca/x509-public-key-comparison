import json

certificate_data = json.loads(open('public_key_comparison_results.json').read())

def perform_crl_check(certificate):
    print("CRL")

def perform_ocsp_check(certificate):
    print("OCSP")

for public_key, certificate_set in certificate_data.items():
    total_num_of_certificates = len(certificate_set)
    num_of_revoced_certificates = 0
    num_of_unknown_certificates = 0
    for certificate in certificate_set:
        is_ocsp_available = type(certificate["OCSP"]) == list and len(certificate["OCSP"]) > 0
        is_crl_available = type(certificate["CrlPoints"]) == list and len(certificate["CrlPoints"]) > 0
        if not(is_crl_available) and not(is_ocsp_available):
            print("Unknown")
            continue
        else:
            if is_ocsp_available:
                perform_ocsp_check(certificate)
            else:
                perform_crl_check(certificate)