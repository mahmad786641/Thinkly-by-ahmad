import os
import json
import uuid
import time
from flask import Flask, request, jsonify, render_template, session, Response, stream_with_context
from flask_cors import CORS
import requests # Ensure you have this installed for API calls

# --- SETUP FOLDERS ---
base_dir = os.path.dirname(os.path.abspath(__file__))
# Point to the 'public' folder located one level up (../public)
template_dir = os.path.join(base_dir, '..', 'public')

# --- INIT APP ---
app = Flask(__name__, template_folder=template_dir, static_folder=template_dir)
app.secret_key = 'your-super-secret-key-change-this-in-production'

# --- CORS CONFIGURATION ---
# This allows your Netlify frontend to talk to this backend, and allows cookies to be sent
CORS(app, supports_credentials=True, origins=[
    "https://thinkly5.netlify.app",
    "http://localhost:5001",
    "http://127.0.0.1:5001"
])

# --- DATABASE HELPERS (JSON based for simplicity) ---
USERS_FILE = os.path.join(base_dir, 'users.json')
RESETS_FILE = os.path.join(base_dir, 'resets.json')

def load_json(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return {}

def save_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

# --- ROUTES ---

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
    
    # FOR PRODUCTION: Change localhost to your Netlify URL
    reset_link = f"https://thinkly5.netlify.app/?reset_token={token}"
    
    # Return the link in dev mode so you can test easily
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

@app.route('/api/chat', methods=['POST'])
def chat():
    # This is where your AI logic goes. 
    # I am providing a mock stream to match your frontend's expectations.
    data = request.json
    user_message = data.get('message', '')
    
    def generate():
        # Mock response streaming
        response_text = f"I am a mock AI. You said: '{user_message}'. To make this real, connect your OpenAI/Groq API in app.py."
        words = response_text.split(' ')
        for word in words:
            # Format expected by frontend: data: {"delta": "..."}
            yield f"data: {json.dumps({'delta': word + ' '})}\n\n"
            time.sleep(0.05) # Simulate typing delay
        
        yield "data: [DONE]\n\n"
        
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

if __name__ == '__main__':
    # Run on port 5001 locally
    app.run(host='0.0.0.0', port=5001, debug=True)