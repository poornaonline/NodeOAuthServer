const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const rateLimit = require("express-rate-limit");

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("./user.model");

const app = express()

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

// This is a sample Mongodb atlas i created for testing perposes;
const MONGO_URL = "mongodb+srv://root:apple@123@cluster0.ye0mq.mongodb.net/oauthnode?retryWrites=true&w=majority";

mongoose.set("useFindAndModify", false);
        mongoose.connect(
            MONGO_URL,
            {
                useCreateIndex: true,
                useNewUrlParser: true,
                useUnifiedTopology: true,
            },
            (error) => {
                if (error) {
                    console.error("Error occurred while connecting to MongoDB: " + error.message);
                } else {
                    console.log("Successfully connected to the MongoDB");
                }
            }
        );

const JWT_SECRET = "POORNA_JAYASINGHE" // This should be a secret and always use an environment variable

app.get('/', (req, res, next) => {
  res.send({
    name: "Poorna Jayasinghe"
  })
})

// Rate limiter to stop password bruteforce attack
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5 // limit each IP to 5 requests per windowMs
});

// Middleware to verify user token
const verifyToken = (req, res, next) => {

  const token = req.headers['accesstoken'];

  if (!token) return res.status(401).send({ 
    success: false,
    message: "Please provide the access token in the header"
  });
  
  jwt.verify(token, JWT_SECRET, async (err, decodedToken) => {

    if (err) {
      return res.status(500).send({
        success: false,
        message: "Invalid token"
      })
    }
      
    let existingUser = await User.findOne({ _id: decodedToken.id });

    if (!existingUser) {
      return res.status(500).send({
        success: false,
        message: "No user account associated with that token"
      })
    }

    next(existingUser);

  });
}

// Test Endpoint (Get User Data)
app.get("/user", verifyToken, async (req, res, next) => {

  let userInfo = req.existingUser;
  userInfo.password = null;

  return res.send({
    success: true,
    user: userInfo
  })
});


app.post('/login', limiter, async (req, res, next) => {

  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) return res.status(401).send({ 
    success: false,
    message: "Please enter credentials"
  });

  try {
    let existingUser = await User.findOne({ email: email });

    if (!existingUser) {
      return res.status(500).send({
        success: false,
        message: "User doesn't exist"
      });
    }

    const isPasswordValid = bcrypt.compareSync(password, existingUser.password);

    if (!isPasswordValid) {
      return res.status(401).send({
        success: false,
        message: "Invalid password"
      });
    }

    const token = jwt.sign({ id: existingUser._id }, JWT_SECRET , {
      expiresIn: 86400 * 30
    });

    console.log(token);
    

    return res.send({
      success: true,
      message: "Login Successful",
      token: token
    })


  } catch (e) {

    return res.status(500).send({
      success: false,
      message: "Error occurred",
      error: e
    })
  }

});

app.post('/register', async (req, res, next) => {

  if (!req.body.password) {
    return res.status(401).send({
      success: false,
      message: "Invalid request",
    });
  }

  const hashedPassword = bcrypt.hashSync(req.body.password);

  try {
    const savedUser = await User.create({
      name : req.body.name,
      email : req.body.email,
      password : hashedPassword
    });

    let token = jwt.sign({id: savedUser._id}, JWT_SECRET, {
      expiresIn: 86400 * 30 // expires in 30 days
    });

    return res.send({
      success: true,
      token: token
    })

  } catch (err) {

    return res.status(500).send({
      success: false,
      message: "Error occurred while saving the user"
    });
  }

});

const PORT = 3000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
