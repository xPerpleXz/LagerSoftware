from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId
from bson.errors import InvalidId
from flask_socketio import SocketIO
import os
import re  

app = Flask(__name__)
app.secret_key = "supergeheimeschluessel"
app.config['DEBUG'] = True
socketio = SocketIO(app, cors_allowed_origins="*")  # CORS aktiviert für Socket.IO

# MongoDB Verbindung
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/lager_db")
app.config["MONGO_URI"] = MONGO_URI
mongo = PyMongo(app)
collection = mongo.db.artikel  # Sammlung für Artikel
bcrypt = Bcrypt(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.benutzer.find_one({"_id": ObjectId(user_id)})
    return User(str(user["_id"]), user["username"]) if user else None

# Registrierung
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            flash("Passwort benötigt Groß-, Kleinbuchstaben, Zahl & Sonderzeichen!", "danger")
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if mongo.db.benutzer.find_one({"username": username}):
            flash("Benutzername existiert bereits!", "danger")
            return redirect(url_for('register'))

        mongo.db.benutzer.insert_one({"username": username, "password": hashed_password})
        flash("Registrierung erfolgreich! Bitte einloggen.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = mongo.db.benutzer.find_one({"username": username})

        if user and bcrypt.check_password_hash(user["password"], password):
            login_user(User(str(user["_id"]), user["username"]))
            flash("Login erfolgreich!", "success")
            return redirect(url_for('index'))
        else:
            flash("Falscher Benutzername oder Passwort!", "danger")

    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Erfolgreich ausgeloggt!", "success")
    return redirect(url_for('login'))

# Startseite mit Bestand
@app.route('/')
@login_required
def index():
    artikel_liste = collection.find()
    return render_template('index.html', artikel=artikel_liste)

# Artikel hinzufügen
@app.route('/artikel', methods=['POST'])
@login_required
def artikel_hinzufuegen():
    ean = request.form.get('ean', '').strip()
    artikelname = request.form['artikelname'].strip()
    menge = int(request.form['menge']) if request.form['menge'] else 0
    preis = float(request.form['preis']) if request.form['preis'] else None

    vorhandener_artikel = collection.find_one({"artikelname": artikelname})

    if vorhandener_artikel:
        if preis is not None and preis != vorhandener_artikel["preis"]:
            flash("Fehler: Artikel existiert bereits! Preis kann nicht geändert werden.", "danger")
            socketio.emit('error_notification', {'message': 'Fehler: Artikel existiert bereits! Preis kann nicht geändert werden.'})
            return redirect(url_for('index'))

        neue_menge = vorhandener_artikel["menge"] + menge
        collection.update_one({"_id": vorhandener_artikel["_id"]}, {"$set": {"menge": neue_menge}})
    else:
        if preis is None:
            flash("Fehler: Neuer Artikel benötigt einen Preis!", "danger")
            return redirect(url_for('index'))

        artikel_data = {"artikelname": artikelname, "menge": menge, "preis": preis}
        if ean:
            artikel_data["ean"] = ean

        collection.insert_one(artikel_data)

    socketio.emit('update', {'message': 'Lagerbestand aktualisiert'})
    return redirect(url_for('index'))

# Artikel entfernen
@app.route('/artikel/entfernen/<id>', methods=['GET'])
@login_required
def artikel_entfernen(id):
    try:
        collection.delete_one({"_id": ObjectId(id)})
        socketio.emit('update', {'message': 'Artikel entfernt'})
    except InvalidId:
        socketio.emit('error_notification', {'message': 'Ungültige Artikel-ID!'})
    return redirect(url_for('index'))

# Artikelbestand aktualisieren
@app.route('/artikel/aktualisieren/<id>', methods=['POST'])
@login_required
def bestand_aktualisieren(id):
    try:
        neue_menge = int(request.form['menge'])
        collection.update_one({"_id": ObjectId(id)}, {"$set": {"menge": neue_menge}})
        socketio.emit('update', {'message': 'Artikelbestand aktualisiert'})
    except InvalidId:
        socketio.emit('error_notification', {'message': 'Ungültige Artikel-ID!'})
    return redirect(url_for('index'))

# Lagerentnahme-Seite
@app.route('/lager_entnahme')
@login_required
def lager_entnahme_seite():
    artikel = list(collection.find())
    return render_template('lager_entnahme.html', artikel=artikel)

# Lagerentnahme durchführen
@app.route('/lager_entnahme/<artikel_id>', methods=['POST'])
@login_required
def lager_entnahme(artikel_id):
    try:
        artikel = collection.find_one({"_id": ObjectId(artikel_id)})

        if not artikel:
            flash("Fehler: Artikel nicht gefunden!", "danger")
            return redirect(url_for('lager_entnahme_seite'))

        entnahme_menge = int(request.form['entnahme'])

        if entnahme_menge <= 0:
            flash("Fehler: Bitte eine positive Zahl eingeben.", "danger")
            return redirect(url_for('lager_entnahme_seite'))

        if artikel["menge"] < entnahme_menge:
            flash(f"Fehler: Nicht genug Bestand! Aktuell: {artikel['menge']}.", "danger")
        else:
            neue_menge = artikel["menge"] - entnahme_menge
            collection.update_one({"_id": ObjectId(artikel_id)}, {"$set": {"menge": neue_menge}})
            socketio.emit('update', {'message': 'Lagerbestand aktualisiert'})
            flash(f"Erfolgreich {entnahme_menge} Stück von {artikel['artikelname']} entnommen. Neuer Bestand: {neue_menge}.", "success")

    except ValueError:
        flash("Ungültige Eingabe! Bitte eine Zahl eingeben.", "danger")

    return redirect(url_for('lager_entnahme_seite'))

# Starten der Anwendung
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
