const express = require('express');
const Datastore = require('nedb-promises'); // DATABASE MODULE
const bcrypt = require('bcryptjs'); // PASSWORD HASHING MODULE
const { validatePassword } = require('./utils/validation'); // PASSWORD VALIDATION FUNCTION
const jwt = require('jsonwebtoken'); // JWT MODULE

const config = require('./config'); // CONFIGURATION MODULE

// Initialize express
const app = express();
const PORT = 3000;

// Configure body parser
app.use(express.json());


const users = Datastore.create({ filename: 'Users.db', autoload: true }); // DATABASE MODULE

app.get('/', (req, res) => {
    res.send('REST API with Node.js, Express, and MongoDB');
});

/*
    POST /api/register
    Registers a new user
    Request body: { name: string, email: string, password: string }
    Response: { message: string, id: string }
*/
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // check if all fields are provided
        if (!name || !email || !password) {
            return res.status(422).json({ error: 'All fields are required (name, email, password)' });
        }

        // email validation for existing user
        if (await users.findOne({ email })) {
            return res.status(409).json({ error: 'Email already exists' });
        }

        // password validation
        if (!validatePassword(password).valid) {
            return res.status(422).json({ error: validatePassword(password).error })
        };

        // wait for password to be hashed
        const hashedPassword = await bcrypt.hash(password, 12);

        const newUser = await users.insert({
            name,
            email,
            password: hashedPassword
        });

        return res.status(201).json({ message: 'User registered successfully', id: newUser._id });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

/*
    POST /api/login
    Logs in a user
    Request body: { email: string, password: string }
    Response: { message: string }
*/
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // check if all fields are provided
        if (!email || !password) {
            return res.status(422).json({ error: 'All fields are required (email, password)' });
        }

        const user = await users.findOne({ email });

        // check if user exists
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Incorrect password' });
        }

        const accessToken = jwt.sign({ userId: user._id }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: '1h' });

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email,
            accessToken
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

