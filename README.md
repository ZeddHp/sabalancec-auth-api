

# 🚀 SABALANCEC Authentication API

## 📜 Overview
This is a secure authentication and authorization REST API built with **Node.js, Express, and NeDB**. It provides user authentication using **JWT (JSON Web Tokens)** and supports access/refresh token management.

## 📁 Project Structure
```
/sabalancec-auth-api
│── /src
│   │── /config             # Configuration files (env, db, secrets)
│   │   ├── config.js
│   │── /middlewares        # Authentication & validation middleware
│   │   ├── authMiddleware.js
│   │── /models             # Database models (NeDB)
│   │   ├── userModel.js
│   │   ├── refreshTokenModel.js
│   │   ├── invalidTokenModel.js
│   │── /utils              # Utility functions (validation, JWT, helpers)
│   │   ├── validation.js
│   ├── index.js
│── .env                    # Environment variables (ignored in Git)
│── .env.example            # Example environment file
│── .gitignore               # Files to ignore
│── package.json            # Dependencies
│── package-lock.json       # Dependency lock file
│── Users.db                # NeDB database file (ignored in .gitignore)
│── UserInvalidTokens.db    # NeDB database file (ignored in .gitignore)
│── UserRefreshTokens.db    # NeDB database file (ignored in .gitignore)
```

---

## ⚡ Setup Guide
### 1️⃣ Clone the Repository
```sh
git clone https://github.com/ZeddHp/sabalancec-auth-api.git
cd sabalancec-auth-api
```

### 2️⃣ Install Dependencies
```sh
npm install
```

### 3️⃣ Setup Environment Variables
1. Create a `.env` file in the root directory.
2. Copy the contents of `.env.example` and paste them into `.env`.
3. Set up the necessary values:
```ini
PORT=3000
ACCESS_TOKEN_SECRET=youraccesstokensecret
ACCESS_TOKEN_EXPIRES_IN=15m
REFRESH_TOKEN_SECRET=yourrefreshtokensecret
REFRESH_TOKEN_EXPIRES_IN=7d
```

### 4️⃣ Start the Server
```sh
npm start
```
or in development mode:
```sh
npm run dev
```

The API will be running at: `http://localhost:3000`

---

## 📖 Swagger API Documentation

This project uses **Swagger** for API documentation. You can access the automatically generated documentation via:

🔗 **Swagger UI-[http://localhost:3000/api-doc](http://localhost:3000/api-docs)**

This documentation allows you to:
- View all available API endpoints.
- Understand required parameters and expected responses.
- Test API endpoints directly from the browser. (doesnt really work)

Swagger API Screenshot![image](https://github.com/user-attachments/assets/d9e956ad-46fa-4869-bef9-aa37e1b135d1)


---

## 🔑 API Endpoints

### **Authentication Routes**
| Method | Endpoint              | Description |
|--------|----------------------|-------------|
| `POST` | `/register`          | Register a new user |
| `POST` | `/login`             | Log in a user and return an access token |
| `POST` | `/refresh-token`     | Refresh access token |
| `POST` | `/logout`            | Log out a user |
| `POST` | `/password/reset`    | Reset user password |

### **User Routes** (`/api/user`)
| Method | Endpoint    | Description |
|--------|------------|-------------|
| `GET`  | `/user`    | Get authenticated user details |
| `PUT`  | `/user`    | Update user profile |

---

## 🔹 Best Practices
- **Use `.env` for secrets and API keys** (never hardcode them in the codebase).
- **Keep dependencies updated** by running `npm update` regularly.
- **Use Git branches** for feature development (`git checkout -b feature-branch`).
- **Run API tests** before pushing changes.

---

## 🚀 Next Steps
- ✅ Add Swagger for API documentation.
- [ ] Implement logging for better debugging.
- [ ] Switch from NeDB to a more scalable DBMS (MongoDB/PostgreSQL).

