from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
import os
import zipfile
from ssl_utils import validate_certificate, get_certificate_expiration, extract_certificate_info
from tinydb import TinyDB, Query
from cryptography import x509
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure folder for uploads and TinyDB
UPLOAD_FOLDER = './uploads'
DB_PATH = './db/certificates.json'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize TinyDB
db = TinyDB(DB_PATH)
Certificate = Query()

# Allowed file extensions for certificate files
ALLOWED_EXTENSIONS = {'crt', 'key', 'pem'}

# Available types of certificates
CERTIFICATE_TYPES = ['Not Specified', 'SSL/TLS', 'Wildcard', 'Self-Signed', 'Multi-Domain', 'Intermediate CA', 'Root CA']

# Check if file has the correct extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Extract the Common Name (CN) from the certificate
def get_common_name(cert_path):
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                return attr.value
    return "Unknown"

@app.route('/')
def index():
    certificates = db.all()  # Assuming `db` is defined somewhere in your app to interact with the database
    return render_template('index.html', certificates=certificates, db=db)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Retrieve uploaded files
        cert_file = request.files.get('certificate')
        key_file = request.files.get('private_key')
        
        # Retrieve form data
        title = request.form.get('title', '')
        cert_type = request.form.get('cert_type', 'Not Specified')
        parent_cert_id = request.form.get('parent_cert_id')

        # Check for valid files
        if not cert_file or not key_file:
            flash('Both certificate and private key files are required.')
            return redirect(request.url)

        if allowed_file(cert_file.filename) and allowed_file(key_file.filename):
            # Secure the filenames
            cert_filename = secure_filename(cert_file.filename)
            key_filename = secure_filename(key_file.filename)
            cert_path = os.path.join(app.config['UPLOAD_FOLDER'], cert_filename)
            key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)

            # Save files to the upload directory
            cert_file.save(cert_path)
            key_file.save(key_path)

            # Extract Common Name (CN) and use as title if no custom title is provided
            common_name = get_common_name(cert_path)
            if not title:
                title = common_name

            # Validate the certificate and key pair
            if validate_certificate(cert_path, key_path):
                expiration_date = get_certificate_expiration(cert_path)
                flash(f"Certificate uploaded successfully! Expires on: {expiration_date}")

                # Save certificate information to TinyDB
                db.insert({
                    'title': title,
                    'cert_filename': cert_filename,
                    'key_filename': key_filename,
                    'cert_path': cert_path,
                    'key_path': key_path,
                    'expiration_date': expiration_date,
                    'uploaded_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'type': cert_type,
                    'parent_cert_id': int(parent_cert_id) if parent_cert_id else None
                })

            else:
                flash('Invalid certificate or key pair!')
                return redirect(request.url)

            return redirect(url_for('index'))

    # For GET request, render the upload form
    parent_certs = db.search((Certificate.type == 'Intermediate CA') | (Certificate.type == 'Root CA'))

    return render_template('upload.html', cert_types=CERTIFICATE_TYPES, parent_certs=parent_certs)

@app.route('/edit/<int:cert_id>', methods=['GET', 'POST'])
def edit_certificate(cert_id):
    cert_data = db.get(doc_id=cert_id)
    
    if cert_data:
        if request.method == 'POST':
            new_title = request.form.get('title', cert_data['title'])
            new_cert_content = request.form['cert_content']
            new_key_content = request.form['key_content']
            new_cert_type = request.form.get('cert_type', cert_data['type'])
            new_parent_cert_id = request.form.get('parent_cert_id', cert_data['parent_cert_id'])

            # Save the new content back to the certificate and key files in binary mode
            with open(cert_data['cert_path'], 'wb') as cert_file:
                cert_file.write(new_cert_content.encode('utf-8'))  # Convert to bytes

            with open(cert_data['key_path'], 'wb') as key_file:
                key_file.write(new_key_content.encode('utf-8'))  # Convert to bytes

            # Validate the new certificate and key pair
            if validate_certificate(cert_data['cert_path'], cert_data['key_path']):
                expiration_date = get_certificate_expiration(cert_data['cert_path'])

                # Update the expiration date and other fields in the database
                db.update({
                    'title': new_title,
                    'expiration_date': expiration_date,
                    'type': new_cert_type,
                    'parent_cert_id': int(new_parent_cert_id) if new_parent_cert_id else None
                }, doc_ids=[cert_id])

                flash(f"Certificate and key updated successfully! New expiration date: {expiration_date}")
            else:
                flash('Invalid certificate or key pair after modification!')
                return redirect(url_for('edit_certificate', cert_id=cert_id))

            return redirect(url_for('view_certificate', cert_id=cert_id))

        # If GET request, load the certificate and key content to the form in binary mode
        with open(cert_data['cert_path'], 'rb') as cert_file:
            cert_content = cert_file.read().decode('utf-8')  # Read in binary mode, then decode to string

        with open(cert_data['key_path'], 'rb') as key_file:
            key_content = key_file.read().decode('utf-8')  # Read in binary mode, then decode to string

        # Fetch all Intermediate and Root CA certificates for selection in the form
        parent_certs = db.search((Certificate.type == 'Intermediate CA') | (Certificate.type == 'Root CA'))

        return render_template('edit.html', cert_data=cert_data, cert_content=cert_content, key_content=key_content, cert_types=CERTIFICATE_TYPES, parent_certs=parent_certs)
    
    else:
        flash("Certificate not found!")
        return redirect(url_for('index'))

@app.route('/view/<int:cert_id>')
def view_certificate(cert_id):
    cert_data = db.get(doc_id=cert_id)
    if cert_data:
        # Fetch parent certificate details if there is a reference
        parent_cert = db.get(doc_id=cert_data['parent_cert_id']) if cert_data.get('parent_cert_id') else None

        # Extract certificate info
        cert_info = extract_certificate_info(cert_data['cert_path'])

        with open(cert_data['cert_path'], 'r') as cert_file:
            cert_content = cert_file.read()

        with open(cert_data['key_path'], 'r') as key_file:
            key_content = key_file.read()

        return render_template('view.html', cert_data=cert_data, cert_content=cert_content, key_content=key_content, parent_cert=parent_cert, cert_info=cert_info)
    
    else:
        flash("Certificate not found!")
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    # Serve the requested file from the uploads directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/download_zip/<int:cert_id>')
def download_zip(cert_id):
    cert_data = db.get(doc_id=cert_id)
    if cert_data:
        zip_filename = f"{cert_data['cert_filename'].rsplit('.', 1)[0]}_cert_bundle.zip"
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], zip_filename)

        # Create a zip file containing the certificate and key
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.write(cert_data['cert_path'], arcname=cert_data['cert_filename'])
            zipf.write(cert_data['key_path'], arcname=cert_data['key_filename'])

        # Send the zip file for download
        return send_from_directory(app.config['UPLOAD_FOLDER'], zip_filename, as_attachment=True)

    flash("Certificate not found!")
    return redirect(url_for('index'))

@app.route('/delete/<int:cert_id>', methods=['POST'])
def delete_certificate(cert_id):
    # Delete certificate entry from database
    certificate = db.get(doc_id=cert_id)
    if certificate:
        # Remove files from disk
        if os.path.exists(certificate['cert_path']):
            os.remove(certificate['cert_path'])
        if os.path.exists(certificate['key_path']):
            os.remove(certificate['key_path'])
        
        db.remove(doc_ids=[cert_id])
        flash(f"Certificate {certificate['title']} deleted successfully!")
    else:
        flash("Certificate not found!")

    return redirect(url_for('index'))

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    if not os.path.exists('./db'):
        os.makedirs('./db')
    app.run(debug=True)
