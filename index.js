const express = require('express');
const Datastore = require('nedb-promises'); // DATABASE MODULE
const bcrypt = require('bcryptjs'); // PASSWORD HASHING MODULE
const { validatePassword } = require('./utils/validation'); // PASSWORD VALIDATION FUNCTION


// Initialize express
const app = express();
const PORT = 3000;

// Configure body parser
app.use(express.json());


const users = Datastore.create({ filename: 'Users.db', autoload: true }); // DATABASE MODULE

app.get('/', (req, res) => {
    res.send('REST API with Node.js, Express, and MongoDB');
});

app.post('/api/register', async (req, res) => {
    // PASSWORD VALIDATION FUNCTION

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

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

