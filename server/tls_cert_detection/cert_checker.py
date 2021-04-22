import datetime
import select
import socket
import sys
import OpenSSL
import json

class Domain(str):
    def __new__(cls, domain):
        host = domain
        port = 443
        connection_host = host
        result = str.__new__(cls, host)
        result.host = host
        result.connection_host = connection_host
        result.port = port
        return result

class CertChecker:
    def __init__(self):
        pass

    def get_cert_from_domain(self, domain):
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        sock = socket.socket()
        sock.settimeout(5)
        wrapped_sock = OpenSSL.SSL.Connection(ctx, sock)
        wrapped_sock.set_tlsext_host_name(domain.host.encode('ascii'))
        wrapped_sock.connect((domain.connection_host, 443))
        while True:
            try:
                wrapped_sock.do_handshake()
                break
            except OpenSSL.SSL.WantReadError:
                select.select([wrapped_sock], [], [])
        return wrapped_sock.get_peer_cert_chain()

    def get_domain_certs(self, domains):
        domain = Domain(domains)
        try:
            data = self.get_cert_from_domain(domain)
        except Exception as e:
            data = e
        return data

    def validate_cert(self, cert_chain):
        msgs = []
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ctx.set_default_verify_paths()
        cert_store = ctx.get_cert_store()
        for index, cert in reversed(list(enumerate(cert_chain))):
            sc = OpenSSL.crypto.X509StoreContext(cert_store, cert)
            try:
                sc.verify_certificate()
            except OpenSSL.crypto.X509StoreContextError as e:
                msgs.append(
                    ('error', "Validation error '%s'." % e))
            if index > 0:
                cert_store.add_cert(cert)
        return msgs


    def check(self, domain,domain_certs,utcnow):
        msgs = []
        results = []

        earliest_expiration = None
        if domain_certs is None: return (msgs, earliest_expiration, None)
        if isinstance(domain_certs, Exception): 
            domain_certs = "".join(traceback.format_exception_only(type(domain_certs),domain_certs)).strip()
        msgs = self.validate_cert(domain_certs)
        for i, cert in enumerate(domain_certs):
            result = {}
            subject = cert.get_subject().commonName
            result["subject"] = subject
            expires = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            result["expires"] = str(expires)

            if expires:
                if earliest_expiration is None or expires < earliest_expiration:
                    earliest_expiration = expires
            issued_level = "info"
            issuer = cert.get_issuer().commonName
            if issuer:
                if issuer.lower() == "happy hacker fake ca":
                    issued_level = "error"
            else:
                issued_level = 'warning'    
            msgs.append((issued_level, "Issued by: %s (subject: %s)" % (issuer, subject)))
            result["issuer"] = issuer

            results.append(result)

            if i < len(domain_certs) - 1:
                sign_cert = domain_certs[i+1]
                subject = sign_cert.get_subject().commonName
                if issuer != subject:
                    msgs.append(
                        ('error', "The certificate sign chain subject '%s' doesn't match the issuer '%s'." % (subject, issuer)))

            sig_alg = cert.get_signature_algorithm()
            if sig_alg.startswith(b'sha1'):
                msgs.append(('error', "Unsecure signature algorithm %s (subject: %s)" % (sig_alg, subject)))
            if expires < utcnow:
                msgs.append(
                    ('error', "The certificate has expired on %s (subject: %s)" % (expires, subject)))
            elif expires < (utcnow + datetime.timedelta(days=15)):
                msgs.append(
                    ('warning', "The certificate expires on %s (%s) (subject: %s)" % (
                        expires, expires - utcnow, subject)))
            else:
                delta = ((expires - utcnow) // 60 // 10 ** 6) * 60 * 10 ** 6
                msgs.append(
                    ('info', "Valid until %s (%s)." % (expires, delta)))
        
        return (msgs, earliest_expiration, results)


    def checkCertChain(self, domain):
        domain = domain.replace("http://","")
        domain = domain.replace("https://","")
        domain = domain.split('/')[0]
        domain_certs = self.get_domain_certs(domain)

        if isinstance(domain_certs, Exception):
            output = {
                "result": "Invalid",
                "errors": ["Unable to obtain certficate chain"],
                "warnings": [],
                "details": []
            }
            return output

        utcnow = datetime.datetime.now()
        (msgs, earliest_expiration, results) = self.check(domain,domain_certs,utcnow)

        warnings = []
        output = {}
        output["details"] = results
        errors = []
        for level, msg in msgs:
            if level == 'error': 
                errors.append(msg)
            elif level == 'warning':
                warnings.append(msg)
        
        output["errors"] = errors
        output["warnings"] = warnings

        if len(errors) > 0:
            output["result"] = "Invalid" 
        elif len(warnings) > 0:
            output["result"] = "Valid (with Warnings)"
        else: output["result"] = "Valid"
        
        return output
