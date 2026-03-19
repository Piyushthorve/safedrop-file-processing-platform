# SafeDrop: Event-Driven Secure File Processing Platform

SafeDrop is a cloud-based file processing system that enables secure uploads, automated PII detection, and redacted file generation using AWS services.

## 🚀 Features
- Secure file upload/download using AWS S3 presigned URLs
- Event-driven processing using AWS Lambda
- Automated PII detection (email, phone, PAN)
- Redacted file generation
- Real-time job tracking with MySQL
- CloudWatch monitoring for observability

## 🏗️ Architecture
1. User uploads file via Spring Boot API
2. File stored in S3 bucket
3. S3 event triggers AWS Lambda
4. Lambda processes file (detects PII & redacts)
5. Processed file stored back in S3
6. Job status updated in MySQL

## 🛠️ Tech Stack
- Backend: Spring Boot
- Cloud: AWS S3, Lambda, EC2
- Database: MySQL
- Messaging: Event-driven (S3 triggers)
- Monitoring: CloudWatch

## 📊 Performance
- Supports 100+ users
- Processed 300+ files
- Improved processing efficiency by ~30% using async architecture

## ▶️ How to Run
1. Start Spring Boot backend
2. Configure AWS credentials
3. Upload file via API
4. Lambda processes file automatically

## 📌 Future Improvements
- Add authentication & access control
- Add real-time notifications
- Enhance NLP-based PII detection
