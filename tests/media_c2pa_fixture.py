"""Ephemeral test-only signing certificates; never production trust anchors."""
import datetime
import io
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def signed_jpeg(source):
    import c2pa
    now = datetime.datetime.now(datetime.timezone.utc)
    rootkey, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    rootname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureSight TEST CA")])
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureSight TEST signer")])
    def base(subject, issuer, public):
        return x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public).serial_number(
            x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
    root = base(rootname, rootname, rootkey.public_key()).add_extension(x509.BasicConstraints(ca=True, path_length=0), True).add_extension(
        x509.KeyUsage(False, False, False, False, False, True, True, False, False), True).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(rootkey.public_key()), False).sign(rootkey, hashes.SHA256())
    cert = base(name, rootname, key.public_key()).add_extension(x509.BasicConstraints(ca=False, path_length=None), True).add_extension(
        x509.KeyUsage(True, False, False, False, False, False, False, False, False), True).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), False).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(rootkey.public_key()), False).sign(rootkey, hashes.SHA256())
    root_pem = root.public_bytes(serialization.Encoding.PEM)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM) + root_pem
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    signer = c2pa.Signer.from_info(c2pa.C2paSignerInfo("es256", cert_pem, private, None))
    destination = io.BytesIO()
    manifest = {"claim_generator": "SecureSight-test/10.0", "title": "Fixture", "format": "image/jpeg",
                "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.created",
                    "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                    "softwareAgent": {"name": "SecureSight Test Generator", "version": "1.0"}}]}}]}
    with c2pa.Context.from_dict({"verify": {"remote_manifest_fetch": False, "ocsp_fetch": False},
            "builder": {"thumbnail": {"enabled": False}}}) as context:
        with c2pa.Builder(manifest, context=context) as builder:
            builder.sign(signer, "image/jpeg", io.BytesIO(source), destination)
    return destination.getvalue(), root_pem.decode()
