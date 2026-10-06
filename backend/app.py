import os
import json
import uuid
import time
import requests
from flask import Flask, request, jsonify, render_template, session, Response, stream_with_context
from flask_cors import CORS

# ==========================================
# 1. SETUP & CONFIGURATION
# ==========================================

# Get the absolute path to the backend folder
base_dir = os.path.dirname(os.path.abspath(__file__))
# Point to the 'public' folder located one level up (../public)
template_dir = os.path.join(base_dir, '..', 'public')

# Initialize Flask App
app = Flask(__name__, template_folder=template_dir, static_folder=template_dir)
app.secret_key = 'your-super-secret-key-change-this-in-production'

# CORS Configuration (Crucial for Netlify -> PythonAnywhere communication)
CORS(app, supports_credentials=True, origins=[
    "https://thinkly5.netlify.app",
    "http://localhost:5001",
    "http://127.0.0.1:5001"
])

# ==========================================
# 2. DATABASE HELPERS (JSON based)
# ==========================================

USERS_FILE = os.path.join(base_dir, 'users.json')
RESETS_FILE = os.path.join(base_dir, 'resets.json')

def load_json(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            content = f.read().strip()
            if not content:  # If the file is empty, return an empty dict
                return {}
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {}
    return {}

def save_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

# ==========================================
# 3. AUTHENTICATION ROUTES
# ==========================================

@app.route('/')
def index():
    # Serve the main index.html from the public folder
    return render_template('index.html')

@app.route('/api/me', methods=['GET'])
def get_current_user():
    if 'username' in session:
        return jsonify({
            'username': session['username'],
            'guest': session.get('guest', False)
        }), 200
    return jsonify({'error': 'Not authenticated'}), 401

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    users = load_json(USERS_FILE)
    
    if username in users and users[username]['password'] == password:
        session['username'] = username
        session['guest'] = False
        return jsonify({'username': username}), 200
    
    return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    users = load_json(USERS_FILE)
    
    if username in users:
        return jsonify({'error': 'Username already exists'}), 400
        
    users[username] = {'password': password}
    save_json(USERS_FILE, users)
    
    session['username'] = username
    session['guest'] = False
    return jsonify({'username': username}), 201

@app.route('/api/guest-login', methods=['POST'])
def guest_login():
    guest_name = f"Guest_{str(uuid.uuid4())[:8]}"
    session['username'] = guest_name
    session['guest'] = True
    return jsonify({'username': guest_name}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'}), 200

# ==========================================
# 4. PASSWORD RESET ROUTES
# ==========================================

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    username = data.get('username')
    
    users = load_json(USERS_FILE)
    if username not in users:
        # Security: Don't reveal if user exists, just pretend it sent
        return jsonify({'message': 'If an account exists, a reset link has been sent.'}), 200
        
    token = str(uuid.uuid4())
    resets = load_json(RESETS_FILE)
    resets[token] = {'username': username, 'timestamp': time.time()}
    save_json(RESETS_FILE, resets)
    
    # In production, you would email this link. 
    # For now, we return it so you can test easily.
    reset_link = f"https://thinkly5.netlify.app/?reset_token={token}"
    
    return jsonify({
        'message': 'Reset link generated.',
        'dev_reset_link': reset_link
    }), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    token = data.get('token')
    new_password = data.get('password')
    
    resets = load_json(RESETS_FILE)
    if token not in resets:
        return jsonify({'error': 'Invalid or expired token'}), 400
        
    username = resets[token]['username']
    
    users = load_json(USERS_FILE)
    if username in users:
        users[username]['password'] = new_password
        save_json(USERS_FILE, users)
        
    # Clean up token
    del resets[token]
    save_json(RESETS_FILE, resets)
    
    return jsonify({'message': 'Password updated successfully', 'username': username}), 200

# ==========================================
# 5. AI CHAT ROUTE (GROQ INTEGRATION)
# ==========================================

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        user_message = data.get('message', '')
        persona = data.get('persona', 'You are a helpful, friendly AI assistant.')
        
        # Get the API key from environment variables
        api_key = os.environ.get("GROQ_API_KEY")        
        if not api_key:
            return jsonify({'error': 'GROQ_API_KEY is not configured. Please set it in your environment variables.'}), 500

        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        # UPDATED: Using a currently supported Groq model
        payload = {
            "model": "openai/gpt-oss-120b",
            "messages": [
                {"role": "system", "content": persona},
                {"role": "user", "content": user_message}
            ],
            "stream": True,
            "temperature": 0.7,
        }

        def generate():
            try:
                with requests.post(url, headers=headers, json=payload, stream=True, timeout=60) as resp:
                    resp.raise_for_status() # Raise exception for 400/500 errors
                    
                    for line in resp.iter_lines():
                        if not line:
                            continue
                        if line.startswith(b"data: "):
                            chunk_data = line[6:]
                            if chunk_data == b"[DONE]":
                                yield "data: [DONE]\n\n"
                                break
                            try:
                                chunk = json.loads(chunk_data)
                                delta = chunk["choices"][0]["delta"]
                                if "content" in delta and delta["content"]:
                                    # Frontend expects: data: {"delta": "text"}
                                    yield f"data: {json.dumps({'delta': delta['content']})}\n\n"
                            except (json.JSONDecodeError, KeyError, IndexError):
                                continue
                                
            except requests.exceptions.HTTPError as e:
                # THIS IS THE KEY DEBUGGING LINE
                print(f"GROQ API HTTP ERROR: {e}")
                print(f"RESPONSE BODY: {e.response.text}") 
                yield f"data: {json.dumps({'delta': f' API Error: {e.response.text}'})}\n\n"
                yield "data: [DONE]\n\n"
            except Exception as e:
                print(f"STREAM ERROR: {e}")
                yield f"data: {json.dumps({'delta': ' Sorry, an error occurred while connecting to the AI.'})}\n\n"
                yield "data: [DONE]\n\n"

        return Response(stream_with_context(generate()), mimetype='text/event-stream')
        
    except Exception as e:
        print(f"CHAT ERROR: {e}")
        return jsonify({'error': str(e)}), 500

# ==========================================
# 6. RUN THE APP
# ==========================================

if __name__ == '__main__':
    # Run on port 5001 locally
    app.run(host='0.0.0.0', port=5001, debug=True)