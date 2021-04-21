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

def get_cert_from_domain(domain):
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

def get_domain_certs(domains):
    domain = Domain(domains)
    try:
        data = get_cert_from_domain(domain)
    except Exception as e:
        data = e
    return data

def validate_cert(cert_chain):
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

def domain_key(d):
    return tuple(reversed(d.split('.')))

def check(domain,domain_certs,utcnow):
    msgs = []
    result = {}
    result["domain"] = domain
    earliest_expiration = None
    if domain_certs is None: return (msgs, earliest_expiration)
    if isinstance(domain_certs, Exception): 
        domain_certs = "".join(traceback.format_exception_only(type(domain_certs),domain_certs)).strip()
    msgs = validate_cert(domain_certs)
    cert = domain_certs[0]
    expires = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    result["expires"] = expires

    if expires:
        if earliest_expiration is None or expires < earliest_expiration:
            earliest_expiration = expires
    issued_level = "info"
    issuer = cert.get_issuer().commonName
    if issuer.lower() == "happy hacker fake ca":
        issued_level = "error"
    msgs.append((issued_level, "Issued by: %s" % issuer))
    result["issuer"] = issuer

    if len(domain_certs) > 1:
        sign_cert = domain_certs[1]
        subject = sign_cert.get_subject().commonName
        if issuer != subject:
            msgs.append(
                ('error', "The certificate sign chain subject '%s' doesn't match the issuer '%s'." % (subject, issuer)))

    sig_alg = cert.get_signature_algorithm()
    if sig_alg.startswith(b'sha1'):
        msgs.append(('error', "Unsecure signature algorithm %s" % sig_alg))
    if expires < utcnow:
        msgs.append(
            ('error', "The certificate has expired on %s." % expires))
    elif expires < (utcnow + datetime.timedelta(days=15)):
        msgs.append(
            ('warning', "The certificate expires on %s (%s)." % (
                expires, expires - utcnow)))
    else:
        delta = ((expires - utcnow) // 60 // 10 ** 6) * 60 * 10 ** 6
        msgs.append(
            ('info', "Valid until %s (%s)." % (expires, delta)))
    alt_names = set()
    for index in range(cert.get_extension_count()):
        ext = cert.get_extension(index)
        if ext.get_short_name() != b'subjectAltName': continue
        alt_names.update(
            x.strip().replace('DNS:', '')
            for x in str(ext).split(','))
    alt_names.add(cert.get_subject().commonName)
    #print(alt_names)
    domainnames = set()
    domainnames.update([domain])
    unmatched = domainnames.difference(alt_names)
    print(unmatched)
    if unmatched:
        msgs.append(
            ('info', "Alternate names in certificate: %s" % ', '.join(
                sorted(alt_names, key=domain_key))))
        if len(domainnames) == 1:
            name = cert.get_subject().commonName
            if name != domain:
                if name.startswith('*.'):
                    name_parts = name.split('.')[1:]
                    name_parts_len = len(name_parts)
                    domain_host_parts = domain.split('.')
                    if (len(domain_host_parts) - name_parts_len) == 1:
                        if domain_host_parts[-name_parts_len:] == name_parts:
                            return (msgs, earliest_expiration, result)
                msgs.append(
                    ('error', "The requested domain %s doesn't match the certificate domain %s." % (domain, name)))
        else:
            msgs.append(
                ('warning', "Unmatched alternate names %s." % ', '.join(
                    sorted(unmatched, key=domain_key))))
    elif domainnames == alt_names:
        msgs.append(
            ('info', "Alternate names match specified domains."))
    else:
        unmatched = alt_names.difference(domainnames)
        msgs.append(
            ('warning', "More alternate names than specified %s." % ', '.join(
                sorted(unmatched, key=domain_key))))

    
    return (msgs, earliest_expiration, result)

# def getCert(domain):
#     port = '443'
#     hostname = domain
#     context = ssl.create_default_context()

#     with socket.create_connection((hostname, port)) as sock:
#         with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#             print(ssock.version())
#             data = json.dumps(ssock.getpeercert())
#             # print(ssock.getpeercert())
#     obj = json.loads(data)
#     #print(data)
#     # print(obj["notAfter"])
#     result = {}
#     result["issuer"] = obj["issuer"][2][0][1]
#     result["expiry"] = obj["notAfter"]
#     result["domain"] = domain
#     expires = datetime.datetime.strptime(obj["notAfter"], '%b %d %H:%M:%S %Y %Z')
#     print(result["issuer"])
#     if result['issuer'].lower() == "happy hacker fake ca":
#         result["issuer"] = None
#     return result

def init(domain):
    domain = domain.replace("http://","")
    domain = domain.replace("https://","")
    domain = domain.split('/')[0]
    domain_certs = get_domain_certs(domain)
    #print(domain_certs)
    exceptions = list(x for x in domain_certs if isinstance(x, Exception))
    utcnow = datetime.datetime.now()
    (msgs, earliest_expiration, result) = check(domain,domain_certs,utcnow)
    if len(exceptions) > (len(domain_certs) / 2): return 0
    warnings = []
    status = 2
    output = {}
    errors = []
    for level, msg in msgs:
        if level == 'error': 
            error.append(msg)
        elif level == 'warning':
            warnings.append(msg)
    if len(errors) > 0:
        output["status"] = 0
        output["errors"] = errors
    elif len(warnings) > 0:
        output["status"] = 1
        output["warnings"] = warnings
    else: output["status"] = 2
    
    return output
    
def main():
    domain = sys.argv[1]
    output = init(domain)
    print(output)

#main()
