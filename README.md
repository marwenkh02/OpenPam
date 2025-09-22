OpenPAM - Privileged Access Management System
OpenPAM is a lightweight, open-source Privileged Access Management (PAM) platform designed for small to medium businesses and DevOps teams. It provides secure credential management, just-in-time access, multi-factor authentication, and session monitoring.

🚀 Features
Secure User Authentication with password complexity enforcement

Multi-Factor Authentication (MFA) support using TOTP

Role-Based Access Control (RBAC) with admin and user roles

Privileged Session Management with timeout controls

Access Request Workflow for just-in-time access

Account Lockout Protection against brute force attacks

RESTful API with FastAPI backend

Modern Web Interface with Next.js frontend

Database Security with SQLAlchemy ORM

🛠️ Technology Stack
Backend
Python 3.8+ - Programming language

FastAPI - Modern web framework

SQLAlchemy - Database ORM

Alembic - Database migrations

JWT - JSON Web Tokens for authentication

Passlib - Password hashing

PyOTP - TOTP-based MFA

Frontend
Next.js 14 - React framework

TypeScript - Type-safe JavaScript

Tailwind CSS - Utility-first CSS framework

React Hooks - State management

Database
SQLite (Development) - Lightweight database

PostgreSQL (Production) - Recommended for production

📋 Prerequisites
Before installing, ensure you have the following installed on your system:

Required Software
Python 3.8 or higher - Download Python

Node.js 16.8 or higher - Download Node.js

Git - Download Git

pip (Python package manager) - Usually comes with Python

Optional (Recommended)
PostgreSQL (for production) - Download PostgreSQL

Docker (for containerization) - Download Docker

🏗️ Project Structure
text
openpam/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── main.py         # FastAPI application
│   │   ├── database.py     # Database configuration
│   │   ├── models.py       # SQLAlchemy models
│   │   ├── schemas.py      # Pydantic schemas
│   │   ├── auth.py         # Authentication utilities
│   │   └── __init__.py
│   ├── alembic/            # Database migrations
│   ├── requirements.txt    # Python dependencies
│   ├── init_db.py          # Database initialization
│   └── migration.py        # Database migration script
├── frontend/               # Next.js frontend
│   ├── app/
│   │   ├── page.tsx        # Home page
│   │   ├── layout.tsx      # Root layout
│   │   ├── globals.css     # Global styles
│   │   ├── login/
│   │   │   └── page.tsx    # Login page
│   │   ├── signup/
│   │   │   └── page.tsx    # Signup page
│   │   ├── dashboard/
│   │   │   └── page.tsx    # Dashboard page
│   │   └── api/
│   │       └── auth/
│   │           └── route.ts # API route handler
│   ├── tailwind.config.js  # Tailwind configuration
│   ├── next.config.js      # Next.js configuration
│   ├── package.json        # Node.js dependencies
│   └── tsconfig.json       # TypeScript configuration
├── docker-compose.yml      # Docker composition
└── README.md              # This file
🚀 Installation Guide
Step 1: Clone the Repository
bash
# Clone the project
git clone <repository-url>
cd openpam

# Or if you have the code locally, navigate to the project directory
cd path/to/openpam
Step 2: Backend Setup
Option A: Using Virtual Environment (Recommended)
bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
Option B: Using Global Python (Not Recommended)
bash
cd backend
pip install -r requirements.txt
Step 3: Database Setup
For SQLite (Development - Default)
bash
# Initialize the database
python init_db.py

# Or run migrations
alembic upgrade head
For PostgreSQL (Production)
Install PostgreSQL and create a database

Update the DATABASE_URL in your environment variables:

bash
# Create .env file in backend directory
echo "DATABASE_URL=postgresql://username:password@localhost:5432/openpam" > .env
Initialize the database:

bash
python init_db.py
Step 4: Frontend Setup
bash
# Navigate to frontend directory
cd frontend

# Install Node.js dependencies
npm install

# Or if using yarn
yarn install
Step 5: Environment Configuration
Backend Environment (.env file in backend directory)
env
DATABASE_URL=sqlite:///./test.db
SECRET_KEY=your-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
Frontend Environment (.env.local file in frontend directory)
env
BACKEND_URL=http://localhost:8000
🏃‍♂️ Running the Application
Development Mode
Terminal 1: Start Backend Server
bash
cd backend

# Activate virtual environment (if using)
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux

# Start FastAPI server with hot reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
Terminal 2: Start Frontend Server
bash
cd frontend

# Start Next.js development server
npm run dev
# or
yarn dev
Production Mode
Using Docker (Recommended for Production)
bash
# Build and start all services
docker-compose up --build

# Or run in detached mode
docker-compose up -d
Manual Production Deployment
bash
# Backend
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Frontend (build first)
cd frontend
npm run build
npm start
🌐 Access the Application
Frontend Application: http://localhost:3000

Backend API: http://localhost:8000

API Documentation: http://localhost:8000/docs
