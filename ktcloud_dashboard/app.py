from flask import Flask, render_template, request, redirect, session, url_for, flash
import requests
import os
from dotenv import load_dotenv
import time
import json
from datetime import datetime, timezone, timedelta
from config.urls import AUTH_URL

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_token_from_user_input(username, password):
    headers = {"Content-Type": "application/json"}
    data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"id": "default"},
                        "password": password
                    }
                }
            },
            "scope": {
                "project": {
                    "name": username,
                    "domain": {"id": "default"}
                }
            }
        }
    }

    print("📤 요청 본문:")
    print(json.dumps(data, indent=2, ensure_ascii=False))

    try:
        response = requests.post(AUTH_URL, json=data, headers=headers)
    except requests.exceptions.RequestException as e:
        print("⚠️ 연결 실패:", e)
        return None

    print("📥 응답 상태코드:", response.status_code)
    print("📥 응답 내용:", response.text)

    if response.status_code == 201:
        token = response.headers.get("X-Subject-Token")
        expires_at = response.json().get("token", {}).get("expires_at")

        session['token'] = token
        session['token_expire'] = expires_at
        session['username'] = username

        print("✅ 토큰 만료 시간:", expires_at)
        return token
    else:
        return None

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    token = get_token_from_user_input(username, password)
    if token:
        return redirect(url_for('dashboard'))
    else:
        flash("로그인 실패: 인증 정보 확인 필요")
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("로그아웃 되었습니다.")
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    token = session.get('token')
    username = session.get('username')
    expires_at = session.get('token_expire')

    if not token or not username or not expires_at:
        flash("세션이 만료되었습니다. 다시 로그인 해주세요.")
        return redirect(url_for('index'))

    expire_dt_utc = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    now_utc = datetime.now(timezone.utc)
    remaining = int((expire_dt_utc - now_utc).total_seconds())

    if remaining <= 0:
        flash("토큰이 만료되었습니다. 다시 로그인 해주세요.")
        return redirect(url_for('index'))

    expire_dt_kst = expire_dt_utc + timedelta(hours=9)
    formatted_expire_kst = expire_dt_kst.strftime("%Y-%m-%d %H:%M:%S")

    return render_template("views/dashboard.html", username=username, expires_at=formatted_expire_kst, remaining=remaining)

@app.route('/view/servers')
def view_servers():
    token = session.get('token')
    username = session.get('username')
    expires_at = session.get('token_expire')

    if not token or not username or not expires_at:
        flash("세션이 만료되었습니다. 다시 로그인 해주세요.")
        return redirect(url_for('index'))

    expire_dt_utc = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    now_utc = datetime.now(timezone.utc)
    remaining = int((expire_dt_utc - now_utc).total_seconds())

    if remaining <= 0:
        flash("토큰이 만료되었습니다. 다시 로그인 해주세요.")
        return redirect(url_for('index'))

    expire_dt_kst = expire_dt_utc + timedelta(hours=9)
    formatted_expire_kst = expire_dt_kst.strftime("%Y-%m-%d %H:%M:%S")

    return render_template("views/servers.html", username=username, expires_at=formatted_expire_kst, remaining=remaining)

@app.route('/view/server/<server_id>')
def server_detail(server_id):
    token = session.get('token')
    username = session.get('username')
    expires_at = session.get('token_expire')

    if not token or not username or not expires_at:
        flash("세션이 만료되었습니다. 다시 로그인 해주세요.")
        return redirect(url_for('index'))

    try:
        headers = {
            'X-Auth-Token': token
        }
        url = f"https://api.ucloudbiz.olleh.com/d1/server/servers/{server_id}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            server_info = response.json().get('servers', {})
        else:
            flash("서버 정보를 불러오는 데 실패했습니다.")
            server_info = {}

    except Exception as e:
        print("❌ 서버 상세 조회 실패:", e)
        flash("서버 정보를 조회하는 중 오류가 발생했습니다.")
        server_info = {}

    expire_dt_utc = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    now_utc = datetime.now(timezone.utc)
    remaining = int((expire_dt_utc - now_utc).total_seconds())

    return render_template("views/server_detail.html", server=server_info, username=username, remaining=remaining)

if __name__ == '__main__':
    app.run(debug=True)
