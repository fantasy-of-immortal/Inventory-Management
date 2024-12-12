import requests
import json

def register():
    url = "http://127.0.0.1:5000/api/users"
    data = {
        "username": "user",
        "password": "123456",
        "role": "user"
    }
    response = requests.post(url, json=data)
    print(response.json())



'''
"username": "root"
"password": "cyz123"
'''

def login():
    url = "http://127.0.0.1:5000/api/users/login"
    data = {
        "username": "user",
        "password": "123456"
    }
    response = requests.post(url, json=data)
    print(response.json())
    return response.json()['token']



def Info(token):
    url = "http://localhost:5000/api/users/me"
    headers = {
        'Authorization': f'Bearer {token}'  # 使用 "Bearer" 前缀和空格
    }
    response = requests.get(url, headers=headers)
    try:
        response_data = response.json()
        if response.status_code == 200:
            print("用户信息:", response_data)
        else:
            print("错误:", response_data)
    except json.decoder.JSONDecodeError:
        print(f"响应不是有效的 JSON，状态码: {response.status_code}")
        print("原始响应内容:", response.text)



if __name__ == "__main__":
    # register()
    token = login()
    Info(token)


