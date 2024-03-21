from flask import Flask,request,render_template
import numpy as np
import joblib
from urllib.parse import urlparse
import tldextract
import unicodedata
import re
import idna
import os.path
from tld import get_tld

app = Flask(__name__)

@app.route("/")
def Home():
    return render_template("Index.html")


def extract_features(url):
    # Initialize feature dictionary
    features = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    arr = np.array(features)
    # {'having_IP':0,'URL_Length':0,'Shortening_Service':0,}
    parsed_url = urlparse(url)
    path = parsed_url.path
    tld = tldextract.extract(url).domain
    # Extract features using regular expressions
    # Check if URL contains an IP address


# 1
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


# 2
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


# 3

# 4
def count_dot(url):
    count_dot = url.count('.')
    return count_dot


# 5
def count_www(url):
    url.count('www')
    return url.count('www')


# 6
def count_atrate(url):
    return url.count('@')


# 7
def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')


# 8
def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')


# 9
def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0


# 10
def count_https(url):
    return url.count('https')


# 11
def count_http(url):
    return url.count('http')


# 12
def count_per(url):
    return url.count('%')


# 13
def count_ques(url):
    return url.count('?')


# 14
def count_hyphen(url):
    return url.count('-')


# 15
def count_equal(url):
    return url.count('=')


# 16
def url_length(url):
    return len(str(url))


# 17
def hostname_length(url):
    return len(urlparse(url).netloc)


# 18
# 19
def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
    if match:
        return 1
    else:
        return 0


# 20
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


# 21
def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


# 22
def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0


# 23
def tld_length(url):
    tld = get_tld(url, fail_silently=True)
    try:
        return len(tld)
    except:
        return -1

    return arr

def extract_features(url):
    # Initialize feature dictionary
    features = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    arr = np.array(features)
    # {'having_IP':0,'URL_Length':0,'Shortening_Service':0,}
    parsed_url = urlparse(url)
    path = parsed_url.path
    tld = tldextract.extract(url).domain
    # Extract features using regular expressions
    # Check if URL contains an IP address
    arr[0] = having_ip_address(url)

    arr[1] = abnormal_url(url)

    # arr[2]= google_index(url)

    # Check if URL contains an '@' symbol
    arr[2] = count_dot(url)

    arr[3] = count_www(url)

    arr[4] = count_atrate(url)

    # Extract number of subdomains
    arr[5] = no_of_dir(url)

    # Extract port number
    arr[6] = no_of_embed(url)

    # Extract HTTPS token information
    arr[7] = shortening_service(url)

    # Extract email submission information
    arr[8] = count_https(url)

    arr[9] = count_http(url)

    # Extract abnormal URL information
    arr[10] = count_per(url)

    arr[11] = count_ques(url)

    arr[12] = count_hyphen(url)

    arr[13] = count_equal(url)

    arr[14] = url_length(url)

    arr[15] = hostname_length(url)

    arr[16] = suspicious_words(url)

    arr[17] = fd_length(url)

    arr[18] = tld_length(url)

    arr[19] = digit_count(url)

    arr[20] = letter_count(url)

    return arr


@app.route("/predict", methods=["GET", "POST"])
def predict():
    url=request.form["url"]
    model=joblib.load('mlp_model.joblib')
    features=extract_features(url)
    results=model.predict([features])
    if results == 0:
        output = "The URL is safe to use."
        return render_template('Result2.html', result=output)
    elif results == 1:
        output="This is a Defacement URL!! Be careful.."
        return render_template('Result1.html', result=output)
    elif results == 2:
        output="This is a Malware URL!!"
        return render_template('Result1.html', result=output)
    elif results == 3:
        output = "This is a Phishing URL!! Be Cautious while entering personal information..."
        return render_template('Result1.html', result=output)
if __name__ == "__main__":
    app.run()

