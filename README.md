**⚡ Setup Guide**

1️⃣ Clone the Repository

    git clone https://github.com/yourusername/sabalancec-auth-api.git
    cd sabalancec-auth-api

2️⃣ Install Dependencies

    npm install

3️⃣ Setup Environment Variables

    Create a .env file in the root directory.
    
    Copy the contents of .env.example and paste them into .env.

Set up the necessary values:

    PORT=3000
    ACCESS_TOKEN_SECRET=youraccesstokensecret
    ACCESS_TOKEN_EXPIRES_IN=15m
    REFRESH_TOKEN_SECRET=yourrefreshtokensecret
    REFRESH_TOKEN_EXPIRES_IN=7d

4️⃣ Start the Server

    npm start
    
    or in development mode:
    
    npm run dev

The API will be running at: http://localhost:3000
