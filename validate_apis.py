import requests
import json
import random

BASE_URL = "https://streammeon-production.up.railway.app"
HEADERS = {"accept": "application/json", "Content-Type": "application/json"}


def register_user():
    role = random.choice(["user", "vendor"])
    num = random.randint(1, 100)
    email = f"{role}{num}@example.com"
    name = f"{role}{num}"
    password = "123456789"

    url = f"{BASE_URL}/auth/register"
    payload = {
        "email": email,
        "name": name,
        "password": password,
        "role": role
    }
    print(f"Registering: {email} as {role}")
    response = requests.post(url, headers=HEADERS, json=payload)
    if response.status_code == 200:
        print(f"Registration successful for {email}")
        return response.json()
    else:
        print(f"Registration failed for {email}: {response.status_code}")
        print(response.json())
        return None


def login_user(email):
    url = f"{BASE_URL}/auth/login"
    payload = {
        "email": email,
        "password": "123456789"
    }
    print(f"Logging in: {email}")
    response = requests.post(url, headers=HEADERS, json=payload)
    if response.status_code == 200:
        print(f"Login successful for {email}")
        return response.json()
    else:
        print(f"Login failed for {email}: {response.status_code}")
        print(response.json())
        return None


def get_user_info(token):
    url = f"{BASE_URL}/me"
    # Try Authorization header first
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    print(f"Fetching user info with token: {token[:10]}... (header)")
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print("User info retrieved successfully")
        return response.json()
    else:
        print(f"Failed to get user info (header): {response.status_code}")
        print(response.json())
        # Try as query parameter
        print("Retrying with token as query parameter")
        response = requests.get(url, headers=HEADERS, params={"authorization": f"Bearer {token}"})
        if response.status_code == 200:
            print("User info retrieved successfully (query)")
            return response.json()
        else:
            print(f"Failed to get user info (query): {response.status_code}")
            print(response.json())
            return None


def create_live_session(token, title):
    url = f"{BASE_URL}/live/sessions"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    payload = {"title": title}
    print(f"Creating live session: {title}")
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        print("Live session created successfully")
        return response.json()
    else:
        print(f"Failed to create live session (header): {response.status_code}")
        print(response.json())
        # Try as query parameter
        print("Retrying with token as query parameter")
        response = requests.post(url, headers=HEADERS, params={"authorization": f"Bearer {token}"}, json=payload)
        if response.status_code == 200:
            print("Live session created successfully (query)")
            return response.json()
        else:
            print(f"Failed to create live session (query): {response.status_code}")
            print(response.json())
            return None


def post_comment(token, session_id, message):
    url = f"{BASE_URL}/live/sessions/{session_id}/comments"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {token}"
    payload = {"message": message}
    print(f"Posting comment: {message}")
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        print("Comment posted successfully")
        return response.json()
    else:
        print(f"Failed to post comment (header): {response.status_code}")
        print(response.json())
        # Try as query parameter
        print("Retrying with token as query parameter")
        response = requests.post(url, headers=HEADERS, params={"authorization": f"Bearer {token}"}, json=payload)
        if response.status_code == 200:
            print("Comment posted successfully (query)")
            return response.json()
        else:
            print(f"Failed to post comment (query): {response.status_code}")
            print(response.json())
            return None


def test_api():
    # Register a random user
    reg_response = register_user()
    if not reg_response:
        return
    email = reg_response["user"]["email"]

    # Test login
    login_response = login_user(email)
    if not login_response:
        return
    token = login_response.get("access_token")
    if not token:
        print("Error: No access_token in login response")
        print(login_response)
        return

    # Test user info
    user_info = get_user_info(token)
    if not user_info:
        return

    # Test creating live session
    session_title = f"Test Live Session {email}"
    session_response = create_live_session(token, session_title)
    if not session_response:
        return

    # Assuming session_response contains session_id
    session_id = session_response.get("id") if isinstance(session_response, dict) else "1"
    print(f"Using session_id: {session_id}")

    # Test posting a comment
    comment_response = post_comment(token, session_id, f"Test comment from {email}")

    # Test getting active sessions
    active_sessions_url = f"{BASE_URL}/live/sessions/active"
    print("Fetching active sessions")
    response = requests.get(active_sessions_url, headers=HEADERS)
    if response.status_code == 200:
        print("Active sessions retrieved successfully")
        print(response.json())
    else:
        print(f"Failed to get active sessions: {response.status_code}")
        print(response.json())


if __name__ == "__main__":
    print("Starting API test...")
    test_api()
    print("API test completed")