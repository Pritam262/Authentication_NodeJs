
const express = require("express")
const { body, validationResult } = require('express-validator')
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const jwtSecretKey = process.env.JWT_SECRETE_KEY
const router = express.Router();
const connectToMongo = require("../db")
const Usermodel = require("../models/User")

// const User = require("../model/User");
const fetchuser = require("../middleware/fetchuser")

// const UserData = require("../model/User")

// Signup api : localhost:3000/api/auth/register
router.post('/register', [
    body('name', "Enter a valid name").optional().trim().isLength({ min: 3 }),
    body('email', "Enter a valid email address").optional().trim().isEmail(),
    body('password', "Enter a valid password").optional().trim().isLength({ min: 8 }),
], async (req, res) => {

    const { name, email, password } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        // console.log("Error", errors)
        return res.status(400).json({ errors: errors.array() })
    }
    // Check the user is exit or not
    try {

        let user = await Usermodel.findOne({ email: email });
        if (user) {
            return res.status(400).json({ error: "Sorry a user with this email is already exits" })
        }


        const salt = await bcrypt.genSalt(10)
        const secPass = await bcrypt.hash(password, salt);
        // Create a new user
        userData = await Usermodel.create({
            name,
            email,
            password: secPass,
            // password: req.body.password
        })

        const data = {
            user: {
                id: userData.id,
            }
        }
        const authtoken = jwt.sign(data, jwtSecretKey)

        // console.log(req.body)
        // console.log(authtoken)

        // res.json(user)
        res.json({ authtoken })
    } catch (error) {
        console.error(error.message)
        res.status(500).send({ error: error.message })
    }

})


//Route 2:  Login a user using POST: "localhost:3000/api/auth/login". No login required
router.post('/login', [
    body('email', "Enter a valid email address").optional().trim().isEmail(),
    body('password', "Password cannot be blank").optional().exists(),
], async (req, res) => {
    // if there are errors, return bad request and the request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    const { email, password } = req.body;
    try {
        let user = await Usermodel.findOne({ email: email });
        if (!user) {
            return res.status(400).json({ error: "Please try to login with currect credentials" })
        }
        const passwordCompare = await bcrypt.compare(password, user.password);
        if (!passwordCompare) {
            return res.status(400).json({ error: "Please try to login with currect credentials" })
        }
        const data = {
            user: {
                id: user.id,
            }
        }
        const authtoken = jwt.sign(data, jwtSecretKey)
        res.json({ authtoken })
    } catch (error) {
        console.error(error.message)
        res.status(500).send("Internal server error")
    }
})


//Route 3:  Get login user details using POST: "localhost:3000/api/auth/getuser". Login required
router.post('/getuser', fetchuser, async (req, res) => {
    try {
        userId = req.user.id;

        const user = await Usermodel.findById(userId).select("-password");
        res.send(user)
    } catch (error) {
        console.error(error.message)
        res.status(500).send("Internal server error")
    }
})

module.exports = router