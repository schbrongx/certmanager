# CertManager

**A lightweight tool to manage SSL/TLS certificates with ease.**


## Summary

CertManager is a simple Flask-based web application designed to help you manage your SSL/TLS certificates effortlessly. With support for uploading certificates and private keys, viewing certificate details, and managing certificate chains, it provides a clean interface with powerful features for handling certificates.

The project was built using the following technologies:
- **Python**
- **Flask** (web framework)
- **Bootstrap** (for UI styling)
- **Font Awesome** (for icons)
- **Jinja2** (for templating)
- **TinyDB** (for lightweight database management)

This project was built in one day using **Python Copilot v2** and **ChatGPT**.


## Features

- Upload and manage SSL/TLS certificates and private keys.
- View detailed certificate information (issuer, subject, validity period, key usage, etc.).
- Support for managing certificate chains (Root CA, Intermediate CA, Leaf certificates).
- Download certificates and keys individually or as a ZIP file.
- Copy certificate/key content to the clipboard with a click.
- Responsive and easy-to-use UI, built with Bootstrap and Font Awesome.


## Getting Started

### Prerequisites

Before you can run the application, make sure you have the following installed:

- **Python 3.7+**
- **pip** (Python package manager)
- **virtualenv** (optional but recommended for isolated environments)

### Installation

1. **Clone the Repository**

   Clone the repository from GitHub:
   ```bash
   git clone https://github.com/your-username/certmanager.git
   cd certmanager
   ```
   
2. **Set Up a Virtual Environment (Optional)**

    It’s a good idea to create a virtual environment to isolate dependencies:
   ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**

    Install the necessary dependencies using pip:
   ```bash
    pip install -r requirements.txt
   ```

4. **Run the Application**

    After installing the dependencies, you can start the Flask development server:
   ```bash
    flask run
   ```
    By default, the app will be available at http://127.0.0.1:5000/.

    Keep in mind that the flask development server is not suitable for a production environment. Consider Running
    Certmanager with gunicorn and ideally place it behind a reverse proxy like Nginx.

    #### Install Gunicorn:

    Gunicorn is a Python WSGI HTTP Server that can serve your Flask app in a production environment:
    ```bash
    pip install gunicorn
    ````

    #### Run Flask  with Gunicorn:
    You can run your Flask app with Gunicorn using the following command:
    ````bash
    gunicorn -w 4 -b 0.0.0.0:8000 app:app
    ````

    Explanation:
    * -w 4: This specifies the number of worker processes to handle requests. Adjust based on your server's resources (e.g., 2-4 workers per CPU core).
    * -b 0.0.0.0:8000: Binds Gunicorn to port 8000. You can adjust this if you prefer a different port.
    * app:app: This refers to your Flask app object. In this case, app.py contains app = Flask(__name__), so app:app is correct.


### Configuration

* The app uses TinyDB to store certificate metadata.
* Certificates and keys will be stored locally.

## Development and Testing

  For testing and development purposes, the project includes a helper script to generate dummy certificates.

### Using the <code>create_dummy_certificates.py</code> Script

  The script located in the <code>tools/</code> directory can be used to generate dummy certificates and private keys for testing.

  To generate a Root CA, Intermediate CA, and Leaf SSL Certificate, run the following command:
   ```bash
    python tools/create_dummy_certificates.py
   ```
  This will generate the following PEM files:

* <code>root_cert.pem</code> / <code>root_key.pem</code>
* <code>intermediate_cert.pem</code> / <code>intermediate_key.pem</code>
* <code>leaf_cert.pem</code> / <code>leaf_key.pem</code>

These certificates can be uploaded into the CertManager app to simulate certificate chains.

## Contributing

Feel free to fork this project and submit pull requests! Any feedback, issues, or improvements are welcome.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

## Copyright

© 2024 Thomas Pesendorfer. All rights reserved.
