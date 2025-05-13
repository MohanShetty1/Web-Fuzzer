import threading
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash,send_file
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from boofuzz import FuzzLoggerText, Session, Target, Request

from web_fuzzer import WebAppFuzzer

app = Flask(__name__)
socketio = SocketIO(app,cors_allowed_origins="*")

# Configure secret key and database
app.secret_key = os.getenv('SECRET_KEY', 'default_fallback_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Create a folder for reports if it doesn't exist
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# User model for database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Home route
@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="Username already exists.")

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            return render_template('login.html', error="Invalid username or password.")

        session['user'] = username
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Dashboard route
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    return render_template('dashboard.html')

# Fuzzing route
'''@app.route('/start_fuzzing', methods=['POST'])
def start_fuzzing():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    target_url = request.json.get('target_url')
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400

    # Define the fuzzing process
    session = Session(target=Target(connection=target_url), fuzz_loggers=[FuzzLoggerText()])
    session.connect(Request("GET", "/"))
    session.fuzz()

    return jsonify({'message': 'Fuzzing started successfully!'}), 200
'''
'''@app.route('/start_fuzzing', methods=['POST'])
def start_fuzzing():
    # Ensure session is accessible
    if 'user' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    data = request.form
    base_url = data.get('baseUrl')
    endpoint = data.get('endpoint')

    if not base_url or not endpoint:
        return render_template('dashboard.html', error="Base URL and endpoint are required.")

    try:
        fuzzer = WebAppFuzzer(base_url)
        results = fuzzer.run(endpoint)
        return render_template('dashboard.html', results=results)

    except Exception as e:
        return render_template('dashboard.html', error=f"Fuzzing error: {str(e)}")
'''
#@app.route('/start_fuzzing', methods=['POST'])
#def start_fuzzing():
    #if 'user' not in session:
    #    return redirect(url_for('login'))
    #data = request.form

    #'''base_url = data.form.get('baseUrl')
    #endpoint = data.form.get('endpoint')'''
    #base_url = request.form.get('baseUrl')
    #endpoint = request.form.get('endpoint')


    #if not base_url:
    #    return jsonify({"error": "Base URL and endpoint is required"}), 400

    #report_path = os.path.join(REPORTS_DIR, f"{session['user']}_fuzzing_report.json")
def run_fuzzing(base_url,endpoint,username):
    """Runs fuzzing in a separate thread and emits progress updates."""
    with app.app_context():  # ✅ FIX: Ensure Flask context is active
        fuzzer = WebAppFuzzer(base_url)
        results = fuzzer.run(endpoint, progress_callback=send_progress)

        #username = session.get('user', 'default')
        # Generate report URL inside context
            #report_url = url_for('get_report')  # ✅ FIX: Now inside app context
            # Save results as a JSON report
        #report_filename = f"{session['user']}_fuzzing_report.json"
        #report_filename = f"{session.get('user','default')}_fuzzing_report.json"
        report_filename = f"{username}_fuzzing_report.json"
        report_path = os.path.join(REPORTS_DIR, report_filename)

        with open(report_path, 'w') as report_file:
            json.dump(results, report_file, indent=4)
        
        #report_url = url_for('get_report', filename=report_filename)
        # Emit event when fuzzing is complete
        #socketio.emit('fuzz_complete', {'message': 'Fuzzing completed!', 'report_url': url_for('get_report', filename=report_filename),'results':results},namespace='/')
        #socketio.emit('fuzz_complete', {'message': 'Fuzzing completed!', 'report_url': report_url,'results':results},namespace='/')
        socketio.emit("fuzz_complete", {"message": "Fuzzing completed!", "report_url": f"/report/{username}"}, namespace="/")

@app.route('/start_fuzzing', methods=['POST'])
def start_fuzzing():
    """Starts the fuzzing process in a new thread."""
    try:
        data = request.get_json()  # ✅ Use request.json instead of request.form
        base_url = data.get('baseUrl')
        endpoint = data.get('endpoint')
        username = session.get('user','default')

        if not base_url or not endpoint:
            return jsonify({'error': 'Missing baseUrl or endpoint'}), 400

        # Start fuzzing in a separate thread
        thread = threading.Thread(target=run_fuzzing, args=(base_url, endpoint,username))
        thread.start()

        return jsonify({'message': 'Fuzzing started successfully'}), 200  # ✅ Return valid response

    except Exception as e:
        return jsonify({'error': str(e)}), 500    

    '''def run_fuzzing(): 
        fuzzer = WebAppFuzzer(base_url)
        results= fuzzer.run(endpoint, progress_callback=send_progress)  # Start fuzzing # Send progress updates

         # Save report
        with open(report_path, "w") as report_file:
            json.dump(results, report_file, indent=4)

        socketio.emit('fuzz_complete', {'message': 'Fuzzing completed!', 'report_url': url_for('get_report')})

    socketio.start_background_task(run_fuzzing)
    return jsonify({"message": "Fuzzing started!",'status': 'running'})'''


def send_progress(current,total):
    """Send real-time progress updates to the frontend."""
    socketio.emit('fuzz_progress', {'current': current,'total':total},namespace='/')
    #print(f"Progress: {current}/{total}")
    
#@app.route('/report/<filename>')
@app.route('/report/<username>')
def get_report(username):
    """Serve the latest fuzzing report."""
    report_path = os.path.join(REPORTS_DIR, f"{username}_fuzzing_report.json")
    #filename = request.args.get('filename')

    '''if not filename:
        return jsonify({'error': 'No filename provided'}), 400
    report_path = os.path.join(REPORTS_DIR, filename)'''
    
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True, mimetype='application/json')
    else:
        return jsonify({'error': 'No report found!'}), 404
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
    #app.run(debug=True)
