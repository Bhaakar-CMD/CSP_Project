# 🌱 Smart Modern Irrigation Recommendation System

An intelligent precision agriculture and water management web platform developed for the Community Service Project (CSP - Group A17). The system recommends optimal irrigation techniques (Drip, Sprinkler, Surface, Subsurface, Center Pivot, Furrow) based on crop selection, soil classification, water availability, and land area, complete with audio/video practical demonstrations in Telugu and English.

---

## 🌟 Key Features

- **Precision Irrigation Recommendations**: Real-time matching based on crop type, soil texture, water levels, and farm acreage.
- **Interactive Multi-Media Tutorials**: Integrated video guides with YouTube-style player settings (Telugu & English audio tracks, speed control, captions, quality switcher).
- **Secure Authentication**:
  - Encrypted password hashing with `bcryptjs`.
  - Cryptographically signed JWT tokens and HTTP-Only cookies.
  - Show / Hide password toggles on login and registration.
- **Protected Routing**:
  - Landing page on `http://localhost:5000` opens the informative First page (`firstpage.html`).
  - Protected Dashboard (`main.html`) and backend recommendation API (`POST /suggest`).
  - Dedicated Logout button in header redirecting back to home.
- **Admin Control Panel**:
  - Directory of all registered users (Name, Email, Join Date, Feedback count).
  - Drill-down view of individual user feedback submissions.
  - Export feedbacks to CSV.

---

## 📁 Project Structure

```
├── Final-ppt.pptx
├── Softwares Used.pdf
├── survey_questions(D18).pdf
├── CSP-Final_Project(A_17)/
│   └── start/
│       ├── .env
│       ├── .env.example
│       ├── check_old_telugu.js
│       ├── backend/
│       │   ├── package.json
│       │   ├── server.js
│       │   └── test_auth.js
│       └── frontend/
│           ├── firstpage.html / firstpage.css
│           ├── login.html / login.css
│           ├── register.html / register.css
│           ├── main.html / main.css
│           ├── admin_login.html
│           ├── admin_feedback.html
│           ├── feedback.html / feedback.css
│           ├── subsidies.html / subsidies.css
│           ├── techniques.html / techniques.css
│           ├── who's.html / who's.css
│           ├── about.html / about.css
│           ├── images/
│           └── videos/
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Node.js (v18 or higher)
- MongoDB Atlas or local MongoDB instance

### 2. Installation
Navigate to the backend directory and install dependencies:
```bash
cd "CSP-Final_Project(A_17)/start/backend"
npm install
```

### 3. Environment Configuration
Create or verify `CSP-Final_Project(A_17)/start/.env`:
```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_TOKEN=supersecrettoken
```

### 4. Running the Server
```bash
npm start
```
The server will start on: `http://localhost:5000`

### 5. Running Automated Tests
```bash
npm test
```

---

## 👥 Authors
- **Bhaskar**
- **Gangadhar**
- **Harsha**
- **Hari Venkat**
