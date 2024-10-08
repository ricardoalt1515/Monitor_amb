import os
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sensores.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    temperature = db.Column(db.Float)
    humidity = db.Column(db.Float)
    co2 = db.Column(db.Integer)
    light = db.Column(db.Integer)
    room = db.Column(db.String(50))

# Configuración
THRESHOLDS = {
    'temperature': {'min': 18, 'max': 28},
    'humidity': {'min': 30, 'max': 60},
    'co2': {'min': 400, 'max': 1000},
    'light': {'min': 300, 'max': 500}
}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rutas de autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Usuario o contraseña inválidos')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Rutas principales
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html', thresholds=THRESHOLDS)

@app.route('/api/historical_data')
@login_required
def historical_data():
    days = request.args.get('days', 7, type=int)
    room = request.args.get('room', 'Sala')
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    data = SensorData.query.filter(
        SensorData.timestamp.between(start_date, end_date),
        SensorData.room == room
    ).all()
    
    return jsonify([{
        'timestamp': record.timestamp.isoformat(),
        'temperature': record.temperature,
        'humidity': record.humidity,
        'co2': record.co2,
        'light': record.light
    } for record in data])

@app.route('/api/rooms')
@login_required
def get_rooms():
    rooms = db.session.query(SensorData.room).distinct().all()
    return jsonify([room[0] for room in rooms])

@app.route('/api/update_thresholds', methods=['POST'])
@login_required
def update_thresholds():
    global THRESHOLDS
    THRESHOLDS = request.json
    return jsonify({"status": "success"})

def get_sensor_data(room):
    return {
        'temperature': round(random.uniform(15, 32), 1),
        'humidity': round(random.uniform(20, 80), 1),
        'co2': round(random.uniform(300, 2000), 0),
        'light': round(random.uniform(0, 1000), 0),
        'room': room
    }

def check_alerts(data):
    alerts = []
    for key, value in data.items():
        if key in THRESHOLDS:
            if value < THRESHOLDS[key]['min']:
                alerts.append(f"{key.capitalize()} bajo en {data['room']}: {value}")
            elif value > THRESHOLDS[key]['max']:
                alerts.append(f"{key.capitalize()} alto en {data['room']}: {value}")
    return alerts

def update_sensor_data():
    with app.app_context():
        rooms = ['Sala', 'Dormitorio', 'Cocina', 'Oficina']
        for room in rooms:
            data = get_sensor_data(room)
            new_record = SensorData(**data)
            db.session.add(new_record)
            db.session.commit()
            
            alerts = check_alerts(data)
            data['alerts'] = alerts
            socketio.emit('update_data', data)

@socketio.on('connect')
def handle_connect():
    print('Cliente conectado')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin')
            admin_user.set_password('password')
            db.session.add(admin_user)
            db.session.commit()
    
    scheduler = BackgroundScheduler()
    scheduler.add_job(update_sensor_data, 'interval', seconds=10)
    scheduler.start()
    
    socketio.run(app, debug=True, use_reloader=False)