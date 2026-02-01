Django Security Scanner (Django REST Framework)
==============================================

Project Description
-------------------
The Django Security Scanner is a web-based security analysis application developed to identify common security misconfigurations and weaknesses in web applications. The backend of the system is implemented using Django REST Framework (DRF), which provides a scalable and structured RESTful API architecture.

The application allows users to submit a target URL through a web interface. The backend processes the request, performs security-related checks such as HTTP security header analysis, and returns structured results. The frontend consumes the REST APIs and presents the findings in a readable format.

This project demonstrates the practical application of cybersecurity concepts, REST API development, and secure web application design.

---

Objectives
----------
The main objectives of this project are:
1. To develop a RESTful backend using Django REST Framework.
2. To analyze web applications for common security misconfigurations.
3. To identify missing or misconfigured HTTP security headers.
4. To ensure secure handling of user inputs and API requests.
5. To implement clean separation between frontend and backend logic.
6. To follow secure coding and deployment best practices.

---

System Overview
---------------
The system follows a client–server architecture:

- The frontend sends requests to REST APIs.
- Django REST Framework handles API requests and responses.
- Security checks are performed on the target URL.
- Results are returned in JSON format.
- The frontend displays the analysis results to the user.

---

Technologies Used
-----------------

Backend:
- Python
- Django
- Django REST Framework

Frontend:
- HTML
- CSS
- JavaScript

Security Concepts:
- HTTP Security Header Analysis
- Input Validation
- Secure API Design
- Configuration Hardening

Database:
- SQLite (used only for development and testing)

Deployment:
- Gunicorn
- Nginx

---

Project Structure
-----------------
security_scanner/

- manage.py                 : Django project entry point
- requirements.txt          : Python dependencies
- scanner/                  : Django app containing API and scanning logic
- security_scanner/         : Project settings and URL configuration
- templates/                : Frontend HTML templates
- static/                   : Static files (CSS, JavaScript)
- staticfiles/              : Collected static files
- deployment/               : Gunicorn and Nginx configuration files
- .gitignore                : Excludes sensitive and environment-specific files

---

How the Security Scanner Works
------------------------------
1. The user enters a target URL through the frontend interface.
2. The frontend sends a request to the Django REST API.
3. The backend validates the input.
4. Security checks are performed on the target application.
5. Results are generated in JSON format.
6. The frontend displays the security analysis output.

---

How to Run the Project
---------------------

Step 1: Clone the Repository
git clone https://github.com/Nithishkumar0713/security_scanner.git

Step 2: Navigate to the Project Directory
cd security_scanner

Step 3: Create and Activate Virtual Environment
python -m venv venv
venv\Scripts\activate

Step 4: Install Required Dependencies
pip install -r requirements.txt

Step 5: Apply Database Migrations
python manage.py migrate

Step 6: Run the Development Server
python manage.py runserver

Step 7: Open the Application
http://127.0.0.1:8000/

---

API Usage
---------
- The backend exposes RESTful APIs using Django REST Framework.
- APIs accept target URLs as input.
- Responses are returned in JSON format.
- API views are separated from business logic.
- Proper error handling and validation are implemented.

---

Security Best Practices Followed
--------------------------------
- Virtual environments are excluded from version control.
- Environment variables are not committed to GitHub.
- Database files are excluded using .gitignore.
- Secure API design principles are followed.
- Separation of concerns between frontend and backend is maintained.

---

Limitations
-----------
- The scanner performs basic security analysis only.
- It does not replace professional penetration testing tools.
- Advanced vulnerability exploitation is not implemented.
- Scan results depend on network availability and target accessibility.

---

Future Enhancements
-------------------
- Authentication and authorization for API access.
- Advanced vulnerability scanning integration.
- Automated security report generation.
- HTTPS certificate and TLS configuration analysis.
- Cloud deployment and containerization support.

---

Academic Relevance
------------------
This project is developed as part of an academic curriculum to demonstrate practical knowledge of cybersecurity, REST API development, and secure web application architecture.

---

Author
------
Name: Nithish Kumar Pamidi  
Degree: Bachelor of Engineering and Technology  
Specialization: Computer Science engineering in  Cybersecurity  

---

Declaration
-----------
This project is intended strictly for academic and educational purposes. Unauthorized scanning or testing of systems without proper permission is prohibited.
