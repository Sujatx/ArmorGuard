# ArmorGuard

ArmorGuard is an autonomous AI pentesting agent designed to proactively probe target web applications for security vulnerabilities and automatically generate severity-scored forensic audit reports. Governed in real time by the ArmorIQ SDK, the agent intercepts intent drifts and prompt injections mid-task, ensuring safe and compliant execution of diagnostic and exploitation tools.

## Running Locally

You can run the entire system using either Docker Compose or via individual service commands.

### Option 1: Docker Compose (Recommended)
From the root directory, execute:
```bash
docker-compose up --build
```
This boots:
- **Frontend** at [http://localhost:3000](http://localhost:3000)
- **Backend** (FastAPI) at [http://localhost:8000](http://localhost:8000)
- **Demo Target** (Flask) at [http://localhost:5000](http://localhost:5000)

### Option 2: Running Services Separately

#### 1. Backend
```bash
cd backend
python -m venv venv
# Activate virtual environment
# Windows:
venv\Scripts\activate
# Unix:
source venv/bin/activate

pip install -r requirements.txt
python main.py
```
Server runs at `http://127.0.0.1:8000`.

#### 2. Frontend
```bash
cd frontend
npm install
npm run dev
```
Client runs at `http://localhost:3000`.

#### 3. Demo Target
```bash
cd demo-target
python -m venv venv
# Activate virtual environment
# Windows:
venv\Scripts\activate

pip install -r requirements.txt
python app.py
```
Demo app runs at `http://127.0.0.1:5000`.

## Architecture, Locked Contracts, and Database Schema
- The full specifications, API endpoint signatures, and database schemas are defined in [BUILDPLAN.md](BUILDPLAN.md) at the repository root.
- The PostgreSQL database schema definition is copied in [schema.sql](backend/database/schema.sql).

## Scaffold State
- **Backend**: Implements Pydantic camelCase serialization over-the-wire for all objects. Out-of-scope/consent validation logic, mismatched consent URLs, and custom tool validation are fully active. All 6 REST routes and native WebSockets are implemented with realistic dummy outputs.
- **Frontend**: Scaffolding initialized using Next.js 14 (App Router) + Tailwind CSS. Home page styled with a dark premium theme.
- **Demo Target**: A minimal Flask application listening on port 5000.

## Team Collaboration & Git Workflow

All teammates work in this shared repository. Follow these steps to set up your environment, contribute code safely, and keep the build plan updated.

### 1. Clone the Repository
```bash
git clone <repository-url>
cd ArmorGuard
```

### 2. Branching Strategy
Never push directly to the `main` branch. Create a feature branch named after your task or feature:
```bash
# Ensure you are on main and up to date
git checkout main
git pull origin main

# Create and switch to your feature branch
# Naming convention: <name>/<feature-short-desc> (e.g. kirti/sidebar-ui or parth/nuclei-wrapper)
git checkout -b <your-name>/<feature-name>
```

### 3. Make Changes and Commit
Make your changes locally. Follow these rules before committing:
- Do NOT modify locked API contracts in `BUILDPLAN.md` or `PROJECT.md` unless agreed upon by the entire team.
- Ensure your changes follow local conventions (snake_case internally in Python backend, camelCase JSON over the wire, etc.).

Commit with clear messages:
```bash
git add .
git commit -m "feat(backend): implement Supabase DB connection layer"
```

### 4. Push and Create a Pull Request
Push your branch to the remote repository:
```bash
git push origin <your-name>/<feature-name>
```
Go to your Git hosting platform (GitHub/GitLab) and create a **Pull Request (PR)** against `main`. Assign another teammate for code review and verification.

### 5. Update the Project Tracker
Once your feature is merged or as you progress, update your checklist status under Section 9 of `PROJECT.md` by checking off completed tasks (`[x]`) or marking in-progress features (`[/]`).

