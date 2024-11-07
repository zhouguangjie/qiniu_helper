# -*- coding: utf-8 -*-
import hmac
from hashlib import sha1
import hashlib
from urllib.parse import urlparse
from base64 import urlsafe_b64encode
import requests, json
import sys, getopt

# api doc: https://developer.qiniu.com/fusion/4243/access-to-the
api_host = "https://api.qiniu.com"
access_key = "AK"
secret_key = "SK"
exists_certs = {}


def md5_file(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def to_btyes(data):
    if isinstance(data, str):
        return data.encode("utf-8")
    return data


def to_str(data):
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return data


# ref: https://developer.qiniu.com/kodo/manual/1231/appendix#1
def urlsafe_base64_encode(data):
    ret = urlsafe_b64encode(to_btyes(data))
    return to_str(ret)


def hmac_sha1(data):
    data = to_btyes(data)
    sk = to_btyes(secret_key)
    hashed = hmac.new(sk, data, sha1)
    return urlsafe_base64_encode(hashed.digest())


def token_of_request(url, body=None, content_type=None):
    parsed_url = urlparse(url)
    query = parsed_url.query
    path = parsed_url.path
    data = path
    if query != "":
        data = "".join([data, "?", query])
    data = "".join([data, "\n"])

    if body:
        mimes = ["application/x-www-form-urlencoded"]
        if content_type in mimes:
            data += body

    sign = hmac_sha1(data)
    # print(sign)
    return "{0}:{1}".format(access_key, sign)


def gen_req_headers(requrl):
    token = token_of_request(requrl)
    headers = {
        "Content-Type": "application/json",
        "Authorization": "QBox {0}".format(token),
    }
    return headers


def load_conf(conf_path):
    global access_key, secret_key
    with open(conf_path, "r") as file:
        jstr = file.read()
        jobj = json.loads(jstr)
        access_key = jobj["accessKey"]
        secret_key = jobj["secretKey"]
        return jobj


def fetch_exists_certs():
    api_path = "sslcert"
    requrl = "{0}/{1}".format(api_host, api_path)
    headers = gen_req_headers(requrl)
    resp = requests.get(requrl, headers=headers)
    if resp.ok:
        jobj = json.loads(resp.text)
        certs = jobj["certs"]
        for cert in certs:
            cert_name = cert["name"]
            cert_id = cert["certid"]
            exists_certs[cert_name] = cert_id
    else:
        print(resp.text)


def read_text_content(path):
    with open(path, "r") as file:
        content = file.read()
        return content


def get_cert_name(cert_path):
    cert_name = "qiniu_helper_{0}".format(md5_file(cert_path))
    return cert_name


def upload_cert(cert_content, key_content, cert_name, common_name):
    api_path = "sslcert"
    requrl = "{0}/{1}".format(api_host, api_path)
    headers = gen_req_headers(requrl)

    if exists_certs.get(cert_name):
        print("cert exists:{0}".format(cert_name))
    else:
        data = {
            "name": cert_name,
            "common_name": common_name,
            "pri": key_content,
            "ca": cert_content,
        }

        resp = requests.post(requrl, headers=headers, json=data)
        if resp.ok:
            jobj = json.loads(resp.text)
            cert_id = jobj["certID"]
            exists_certs[cert_name] = cert_id
            print("new cert uploaded:{0} #id<{1}>".format(cert_name, cert_id))
        else:
            print(resp.text)


def delete_cert(cert_id):
    api_path = "sslcert"
    requrl = "{0}/{1}/{2}".format(api_host, api_path, cert_id)
    headers = gen_req_headers(requrl)
    resp = requests.delete(requrl, headers=headers)
    if resp.ok:
        for k, v in exists_certs:
            if v == cert_id:
                exists_certs.pop(k)
                break
        print("cert deleted:{0}".format(cert_id))
    else:
        print(resp.text)


def get_domain_info(domain):
    api_path = "domain/{0}".format(domain)
    requrl = "{0}/{1}".format(api_host, api_path)
    headers = gen_req_headers(requrl)
    resp = requests.get(requrl, headers=headers)
    if resp.ok:
        return json.loads(resp.text)
    else:
        return None


def bind_domain_cert(domain, cert_id, forceHttps, http2Enable):
    api_path = "domain/{0}/httpsconf".format(domain)
    requrl = "{0}/{1}".format(api_host, api_path)
    headers = gen_req_headers(requrl)
    data = {"certId": cert_id, "forceHttps": forceHttps, "http2Enable": http2Enable}
    resp = requests.put(requrl, headers=headers, json=data)
    if resp.ok:
        print("new cert binded:{0}#id<{1}>".format(domain, cert_id))
    else:
        print(resp.text)


def renew_domain_cert(conf_path):
    conf = load_conf(conf_path)
    fetch_exists_certs()

    certs = conf["certs"]
    for cert in certs:
        cert_path = cert["cert"]
        cert_key_path = cert["key"]
        common_name = cert["commonName"]
        domains = cert["domains"]
        cert_name = get_cert_name(cert_path)
        cert_id = None
        cert_id = exists_certs.get(cert_name)
        if cert_id:
            print("exists cert:{0}#id:<{1}>".format(cert_name, cert_id))
        else:
            cert_content = read_text_content(cert_path)
            key_content = read_text_content(cert_key_path)
            upload_cert(cert_content, key_content, cert_name, common_name)
            cert_id = exists_certs.get(cert_name)

        for domain in domains:
            if cert_id:
                domain_info = get_domain_info(domain)
                https = domain_info["https"]
                if https:
                    if cert_id != https["certId"]:
                        forceHttps = https["forceHttps"]
                        http2Enable = https["http2Enable"]
                        bind_domain_cert(domain, cert_id, forceHttps, http2Enable)
                    else:
                        print("already binded:{0}:#id<{1}>".format(domain, cert_id))
                else:
                    bind_domain_cert(domain, cert_id, False, False)


def print_help():
    print("qiniu helper")
    # print("--cert_name <cert path>  :print the md5 hash cert name")
    print("--renew <config>         :renew domain cert with a config")
    print("-h                       :print help")


# main
argv = sys.argv[1:]
try:
    opts, args = getopt.getopt(argv, "h", ["renew=", "cert_name="])
except getopt.GetoptError:
    print_help()
    sys.exit(2)
for opt, arg in opts:
    if opt == "-h":
        print_help()
        sys.exit()
    elif opt == "--cert_name":
        print("cert_name: {0}".format(get_cert_name(arg)))
        sys.exit()
    elif opt in ("--renew"):
        print("renew domain cert with config: {0}".format(arg))
        renew_domain_cert(arg)
        sys.exit()

print_help()
