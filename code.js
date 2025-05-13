// /* Passport (For auth) //

const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const User = require("../models/User");

module.exports = function (passport) {
  passport.use(
    new LocalStrategy(
      { usernameField: "email" },
      async (email, password, done) => {
        try {
          const user = await User.findOne({ email: email.toLowerCase() });

          if (!user) {
            return done(null, false, { message: `Email ${email} not found` });
          }
          if (!user.password) {
            return done(null, false, { message: `Invalid password.` });
          }

          user.comparePassword(password, (err, isMatch) => {
            if (err) {
              return done(err);
            }
            if (isMatch) {
              return done(null, user);
            }
            return done(null, false, { msg: "Invalid email or password" });
          });
        } catch (error) {
          console.error(error);
          return done(err);
        }
      }
    )
  );

  passport.serializeUser(function (user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(async function (id, done) {
    try {
      const user = await User.findById(id);
      return done(null, user);
    } catch (err) {
      console.error(err);
      return done(err);
    }
  });
};
// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// auth middleware
module.exports = {
  ensureAuth: (req, res, next) => {
    if (req.isAuthenticated()) {
      return next();
    } else {
      res.redirect("/");
    }
  },
};

//  Session (For storing session in mongodb) //
const session = require("express-session");
const MongoStore = require("connect-mongo");

app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.DB_STRING }),
  })
);

//Connect to Database Function //
const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.DB_STRING);
    console.log(`Mongodb Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
};

module.exports = connectDB;

// User model (with bcrypt for salting pass) //

const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const UserSchema = new mongoose.Schema({
  userName: {
    type: String,
    unique: true,
  },
  email: {
    type: String,
    unique: true,
  },
  password: String,
});

// Password hash middleware
UserSchema.pre("save", function save(next) {
  const user = this;
  if (!user.isModified("password")) {
    return next();
  }
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      return next(err);
    }
    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) {
        return next(err);
      }
      user.password = hash;
      next();
    });
  });
});

// Helper method for validating user's password.

UserSchema.methods.comparePassword = function comparePassword(
  candidatePassword,
  cb
) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    cb(err, isMatch);
  });
};

module.exports = mongoose.model("User", UserSchema);

//  Multer (middleware helps in storing media to cloudinary or any other db) //
const multer = require("multer");
const path = require("path");

module.exports = multer({
  storage: multer.diskStorage({}),
  fileFilter: (req, file, cb) => {
    let ext = path.extname(file.originalname);
    if (ext !== ".jpg" && ext !== ".jpeg" && ext !== ".png") {
      cb(new Error("File type is not supported"), false);
      return;
    }
    cb(null, true);
  },
});

// /* Cloudinary (for storing media files ) //
const cloudinary = require("cloudinary").v2;

require("dotenv").config({ path: "./config/.env" });

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

module.exports = cloudinary;

// /* Basic Auth Controller Template //
const passport = require("passport");
const validator = require("validator");
const User = require("../models/User");

module.exports = {
  getLogin: (req, res) => {
    if (req.user) {
      return res.redirect("/todos");
    }
    res.render("login", {
      title: "Login",
    });
  },
  postLogin: (req, res, next) => {
    const validationErrors = [];
    if (!validator.isEmail(req.body.email))
      validationErrors.push({ msg: "Please enter a valid email address." });
    if (validator.isEmpty(req.body.password))
      validationErrors.push({ msg: "Password cannot be blank." });

    if (validationErrors.length) {
      req.flash("errors", validationErrors);
      return res.redirect("/login");
    } else {
      req.body.email = validator.normalizeEmail(req.body.email, {
        gmail_remove_dots: false,
      });

      passport.authenticate("local", (err, user, info) => {
        if (err) {
          return next(err);
        }
        if (!user) {
          req.flash("errors", info);
          return res.redirect("/login");
        }
        req.logIn(user, (err) => {
          if (err) {
            console.error("Login Error:", err);
            req.flash("errors", { msg: "Login Failed! Please try again." });
            return res.redirect("/todos");
          }
          req.flash("success", { msg: "Success! You are logged in." });
          return res.redirect(req.session.returnTo || "/todos");
        });
      })(req, res, next);
    }
  },
  logout: (req, res) => {
    req.logout((err) => {
      if (err) {
        console.error("Logout error", err);
        return res.redirect("/");
      }
      req.session.destroy((err) => {
        if (err) {
          console.error("Failed to destroy session during logout", err);
        }
        req.user = null;
        return res.redirect("/");
      });
    });
  },
  getSignup: (req, res) => {
    if (req.user) {
      return res.redirect("/todos");
    }
    res.render("signup", {
      title: "Create Account",
    });
  },
  postSignup: async (req, res, next) => {
    let { userName, email, password, confirmPassword } = req.body;
    const validationErrors = [];

    if (!validator.isEmail(email))
      validationErrors.push({ msg: "Please enter a valid email address." });
    if (!validator.isLength(password, { min: 8 }))
      validationErrors.push({
        msg: "Password must be at least 8 characters long",
      });
    if (password !== confirmPassword)
      validationErrors.push({ msg: "Passwords do not match" });

    if (validationErrors.length) {
      req.flash("errors", validationErrors);
      return res.redirect("../signup");
    }
    email = validator.normalizeEmail(email, { gmail_remove_dots: false });

    try {
      const existingUser = await User.findOne({
        $or: [{ email: email }, { userName: userName }],
      });

      if (existingUser) {
        req.flash("errors", {
          msg: "Account with that email address or username already exists.",
        });
        return res.redirect("../signup");
      }

      const user = new User({
        userName: userName,
        email: email,
        password: password,
      });

      await user.save();
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        res.redirect("/todos");
      });
    } catch (err) {
      console.error(err);
      return next(err);
    }
  },
};

// /* Basic CRUD operation controllers //
const cloudinary = require("../middleware/cloudinary");
const Post = require("../models/Post");

module.exports = {
  getProfile: async (req, res) => {
    try {
      const posts = await Post.find({ user: req.user.id });
      res.render("profile.ejs", { posts: posts, user: req.user });
    } catch (err) {
      console.log(err);
    }
  },
  getFeed: async (req, res) => {
    try {
      const posts = await Post.find().sort({ createdAt: "desc" }).lean();
      res.render("feed.ejs", { posts: posts });
    } catch (err) {
      console.log(err);
    }
  },
  getPost: async (req, res) => {
    try {
      const post = await Post.findById(req.params.id);
      res.render("post.ejs", { post: post, user: req.user });
    } catch (err) {
      console.log(err);
    }
  },
  createPost: async (req, res) => {
    try {
      // Upload image to cloudinary
      const result = await cloudinary.uploader.upload(req.file.path);

      await Post.create({
        title: req.body.title,
        image: result.secure_url,
        cloudinaryId: result.public_id,
        caption: req.body.caption,
        likes: 0,
        user: req.user.id,
      });
      console.log("Post has been added!");
      res.redirect("/profile");
    } catch (err) {
      console.log(err);
    }
  },
  likePost: async (req, res) => {
    try {
      await Post.findOneAndUpdate(
        { _id: req.params.id },
        {
          $inc: { likes: 1 },
        }
      );
      console.log("Likes +1");
      res.redirect(`/post/${req.params.id}`);
    } catch (err) {
      console.log(err);
    }
  },
  deletePost: async (req, res) => {
    try {
      // Find post by id
      let post = await Post.findById({ _id: req.params.id });
      // Delete image from cloudinary
      await cloudinary.uploader.destroy(post.cloudinaryId);
      // Delete post from db
      await Post.remove({ _id: req.params.id });
      console.log("Deleted Post");
      res.redirect("/profile");
    } catch (err) {
      res.redirect("/profile");
    }
  },
};

// /* Routes Template //
const express = require("express");
const router = express.Router();
const authController = require("../controllers/auth");
const homeController = require("../controllers/home");
const postsController = require("../controllers/posts");
const { ensureAuth, ensureGuest } = require("../middleware/auth");

//Main Routes - simplified for now
router.get("/", homeController.getIndex);
router.get("/profile", ensureAuth, postsController.getProfile);
router.get("/feed", ensureAuth, postsController.getFeed);
router.get("/login", authController.getLogin);
router.post("/login", authController.postLogin);
router.get("/logout", authController.logout);
router.get("/signup", authController.getSignup);
router.post("/signup", authController.postSignup);

module.exports = router;

/* EJS template
  <%- include('partials/header') -%>

    <h1>Todos</h1>
    <ul>
    <% todos.forEach( el => { %>
            <li class='todoItem' data-id='<%=el._id%>'>
                <span class='<%= el.completed === true ? 'completed' : 'not'%>'><%= el.todo %></span>
                <span class='del'> Delete </span>
            </li>
    <% }) %>    
    </ul>

    <h2><%= user.userName %> has <%= left %> things left to do.</h2>

    <form action="/todos/createTodo" method='POST'>
        <input type="text" placeholder="Enter Todo Item" name='todoItem'>
        <input type="submit">
    </form>

    <a href="/logout">Logout</a>

    <script src="js/main.js"></script>

<%- include('partials/footer') -%>

// Partials (Header)
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Binary Upload Boom</title>
    <link
      rel="icon"
      type="image/png"
      sizes="32x32"
      href="/imgs/favicon-32x32.png"
    />
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css"
      rel="stylesheet"
      integrity="sha384-eOJMYsd53ii+scO/bJGFsiCZc+5NDVN2yr8+0RDqr0Ql0h+rP48ckxlpbzKgwra6"
      crossorigin="anonymous"
    />
    <link
      rel="stylesheet"
      href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css"
      integrity="sha512-iBBXm8fW90+nuLcSKlbmrPcLa0OT92xO1BIsZ+ywDWZCvqsWgccV3gFoRBv0z+8dLJgyAHIhR35VZc2oM/gI1w=="
      crossorigin="anonymous"
    />
    <link rel="stylesheet" href="/css/style.css" />
  </head>
  <body>
    <header class="container">
      <div class="text-center">
        <h1 class=""><a href="/profile">Binary Upload Boom</a></h1>
        <span>The #100Devs Social Network</span>
      </div>
    </header>
  </body>
</html>


// Partials(Footer)
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/js/bootstrap.bundle.min.js" integrity="sha384-JEW9xMcG8R+pH31jmWH6WWP0WintQrMb4s7ZOdauHnUtxwoG2vI5DkLtS3qm9Ekf" crossorigin="anonymous"></script>   
</body>
</html>
*/
