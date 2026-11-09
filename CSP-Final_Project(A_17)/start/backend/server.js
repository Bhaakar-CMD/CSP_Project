const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");

// Multi-path .env loader for local and deployment flexibility
const envPaths = [
  path.resolve(__dirname, "../.env"),
  path.resolve(__dirname, "../../.env"),
  path.resolve(process.cwd(), "CSP-Final_Project(A_17)/start/.env"),
  path.resolve(process.cwd(), "start/.env"),
  path.resolve(process.cwd(), ".env"),
];
for (const ep of envPaths) {
  if (fs.existsSync(ep)) {
    require("dotenv").config({ path: ep });
    break;
  }
}
require("dotenv").config();

const app = express();

// ==========================================
// ENVIRONMENT VARIABLES
// ==========================================

const PORT = process.env.PORT || 5000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "supersecrettoken";
const JWT_SECRET = process.env.JWT_SECRET || "smart-irrigation-jwt-secret-key-2026-secure-token";

// ==========================================
// MONGODB CONNECTION CACHING (SERVERLESS & LOCAL)
// ==========================================

let cachedDbPromise = null;

async function connectToDatabase() {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (cachedDbPromise) {
    return cachedDbPromise;
  }

  const uri = process.env.MONGO_URI;
  if (!uri) {
    throw new Error(
      "MONGO_URI environment variable is missing. In Vercel, please add MONGO_URI in Project Settings > Environment Variables."
    );
  }

  cachedDbPromise = mongoose
    .connect(uri, {
      serverSelectionTimeoutMS: 8000,
      connectTimeoutMS: 8000,
    })
    .then((m) => {
      console.log(
        "MongoDB Connected successfully. Database:",
        m.connection.name
      );
      return m.connection;
    })
    .catch((err) => {
      cachedDbPromise = null;
      console.error("MongoDB Connection Failed:", err.message);
      throw err;
    });

  return cachedDbPromise;
}

// ==========================================
// MIDDLEWARE
// ==========================================

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection middleware for routes requiring MongoDB
async function ensureDb(req, res, next) {
  if (mongoose.connection.readyState === 1 || process.env.NODE_ENV === "test") {
    return next();
  }
  try {
    await connectToDatabase();
    return next();
  } catch (err) {
    console.error("Database Connection Middleware Error:", err.message);
    const isAtlasWhitelist =
      err.name === "MongooseServerSelectionError" ||
      (err.message && err.message.includes("Could not connect to any servers"));

    const hint = isAtlasWhitelist
      ? " MongoDB Atlas is blocking Vercel. In MongoDB Atlas, go to Network Access -> Add IP Address -> Select 'Allow Access from Anywhere' (0.0.0.0/0)."
      : " Please verify your MONGO_URI in Vercel Project Settings > Environment Variables.";

    return res.status(500).json({
      message: "Database connection failed." + hint,
      error: process.env.NODE_ENV === "production" ? undefined : err.message,
    });
  }
}

// ==========================================
// USER SCHEMA AND MODEL
// ==========================================

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  email: {
    type: String,
    trim: true,
    default: "",
  },
  password: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model("User", userSchema);

// ==========================================
// IRRIGATION METHOD SCHEMA AND MODEL
// Uses the existing MongoDB Methods collection
// ==========================================

const methodSchema = new mongoose.Schema(
  {
    crop: String,
    soil: String,
    water: String,
    area: mongoose.Schema.Types.Mixed,
    recommended_method: String,
    description: String,
    video_url: String,
    video_external_url: String,
    video_title: String,
    video_source: String,
    video_description: String,
    video_teaches: [String],
    local_video_url: String,
    image_url: String,
  },
  {
    collection: "Methods",
  }
);

const Method = mongoose.model("Method", methodSchema);

// ==========================================
// FEEDBACK SCHEMA AND MODEL
// ==========================================

const feedbackSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.Mixed,
    default: null,
  },
  username: {
    type: String,
    default: "",
  },
  name: String,
  email: String,
  rating: Number,
  like: String,
  improve: String,
  comments: String,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Feedback = mongoose.model("Feedback", feedbackSchema);

// ==========================================
// SECURE TOKEN HELPERS (HMAC-SHA256 JWT)
// ==========================================

function generateToken(payload) {
  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" })
  ).toString("base64url");
  const exp = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60; // 7 days expiration
  const body = Buffer.from(
    JSON.stringify({ ...payload, exp })
  ).toString("base64url");
  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(`${header}.${body}`)
    .digest("base64url");
  return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, signature] = parts;
  const expectedSig = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(`${header}.${body}`)
    .digest("base64url");
  if (signature !== expectedSig) return null;
  try {
    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    );
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null; // Expired
    }
    return payload;
  } catch (e) {
    return null;
  }
}

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(";").forEach((cookie) => {
      const parts = cookie.split("=");
      const name = parts.shift().trim();
      if (name) list[name] = decodeURIComponent(parts.join("="));
    });
  }
  return list;
}

// ==========================================
// AUTHENTICATION MIDDLEWARES
// ==========================================

function getAuthenticatedUser(req) {
  let token = null;

  // 1. Check Authorization Bearer header
  const auth = req.headers.authorization;
  if (auth && auth.startsWith("Bearer ")) {
    token = auth.slice(7).trim();
  }

  // 2. Check HTTP cookie
  if (!token) {
    const cookies = parseCookies(req);
    token = cookies.authToken || cookies.token;
  }

  if (!token) return null;
  return verifyToken(token);
}

function requireUserAuth(req, res, next) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({
      message: "Unauthorized: Please log in to access this resource.",
    });
  }
  req.user = user;
  return next();
}

function requireAdminAuth(req, res, next) {
  const auth = req.headers.authorization;

  if (
    auth &&
    auth.startsWith("Bearer ") &&
    auth.slice(7) === ADMIN_TOKEN
  ) {
    return next();
  }

  return res.status(401).json({
    message: "Unauthorized: Admin only.",
  });
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ==========================================
// ADMIN LOGIN
// ==========================================

app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === ADMIN_USERNAME &&
    password === ADMIN_PASSWORD
  ) {
    return res.json({
      token: ADMIN_TOKEN,
    });
  }

  return res.status(401).json({
    message: "Invalid admin credentials.",
  });
});

// ==========================================
// USER REGISTRATION
// ==========================================

app.post("/register", ensureDb, async (req, res) => {
  try {
    const { username, email, password, confirm } = req.body;

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      typeof confirm !== "string" ||
      !username.trim() ||
      !password ||
      !confirm
    ) {
      return res.status(400).json({
        message: "Please fill in all required fields.",
      });
    }

    if (password !== confirm) {
      return res.status(400).json({
        message: "Passwords do not match.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters long.",
      });
    }

    const cleanUsername = username.trim();
    const cleanEmail = typeof email === "string" ? email.trim() : "";

    const existingUser = await User.findOne({
      username: new RegExp(`^${escapeRegex(cleanUsername)}$`, "i"),
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Username already exists. Please choose another username.",
      });
    }

    if (cleanEmail) {
      const existingEmail = await User.findOne({
        email: new RegExp(`^${escapeRegex(cleanEmail)}$`, "i"),
      });
      if (existingEmail) {
        return res.status(409).json({
          message: "Email is already registered. Please log in or use another email.",
        });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      username: cleanUsername,
      email: cleanEmail,
      password: hashedPassword,
    });

    return res.status(201).json({
      message: "User registered successfully! You can now log in.",
      user: {
        id: newUser._id,
        username: newUser.username,
      },
    });
  } catch (error) {
    console.error("Registration Error:", error);

    if (error.code === 11000) {
      return res.status(409).json({
        message: "Username already exists.",
      });
    }

    return res.status(500).json({
      message: "Server error during registration.",
    });
  }
});

// ==========================================
// USER LOGIN
// ==========================================

app.post("/login", ensureDb, async (req, res) => {
  try {
    const loginIdentifier = (
      req.body.identifier ||
      req.body.username ||
      req.body.email ||
      ""
    ).trim();
    const password = req.body.password;

    if (!loginIdentifier || typeof password !== "string" || !password) {
      return res.status(400).json({
        message: "Username/Email and password are required.",
      });
    }

    // Support logging in via Username OR Email
    const user = await User.findOne({
      $or: [
        { username: new RegExp(`^${escapeRegex(loginIdentifier)}$`, "i") },
        { email: new RegExp(`^${escapeRegex(loginIdentifier)}$`, "i") },
      ],
    });

    if (!user) {
      return res.status(401).json({
        message: "Invalid username/email or password.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid username/email or password.",
      });
    }

    // Generate secure 7-day token
    const token = generateToken({
      userId: user._id.toString(),
      username: user.username,
      email: user.email || "",
    });

    // Set secure HTTP-only cookie
    res.setHeader(
      "Set-Cookie",
      `authToken=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 24 * 3600}`
    );

    return res.status(200).json({
      message: "Login successful!",
      token: token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email || "",
      },
      redirectUrl: "main.html",
    });
  } catch (error) {
    console.error("Login Error:", error);
    const isDbError =
      error.name === "MongooseServerSelectionError" ||
      (error.message && error.message.includes("Could not connect"));

    const message = isDbError
      ? "Database connection failed. Please ensure MongoDB Atlas Network Access allows 0.0.0.0/0 (anywhere)."
      : "Server error during login.";

    return res.status(500).json({
      message,
      error: process.env.NODE_ENV === "production" ? undefined : error.message,
    });
  }
});

// ==========================================
// USER LOGOUT
// ==========================================

app.post("/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "authToken=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
  );
  return res.status(200).json({
    message: "Logged out successfully.",
    redirectUrl: "firstpage.html",
  });
});

app.get("/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "authToken=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
  );
  return res.redirect("/firstpage.html?logged_out=1");
});

// ==========================================
// VERIFY CURRENT SESSION / USER
// ==========================================

app.get("/api/auth/me", requireUserAuth, (req, res) => {
  return res.status(200).json({
    authenticated: true,
    user: req.user,
  });
});

// ==========================================
// SUGGEST IRRIGATION METHOD (PROTECTED)
// ==========================================

function getMethodMedia(methodName) {
  const name = String(methodName || "").toLowerCase();
  if (name.includes("furrow")) {
    const videoUrl = "https://youtu.be/LfcFprFY9Ig?si=0voBFs2yUBRKBIyi";
    return {
      method: "Furrow Irrigation",
      image: "images/Furrow.jpg",
      video: videoUrl,
      telugu: videoUrl,
      english: videoUrl,
    };
  } else if (name.includes("subsurface")) {
    const videoUrl = "https://www.youtube.com/embed/sH3jQ4ziQ_k";
    return {
      method: "Subsurface Irrigation",
      image: "images/subsurface.jpg",
      video: videoUrl,
      telugu: videoUrl,
      english: videoUrl,
    };
  } else if (name.includes("sprinkler")) {
    const videoUrl = "https://youtu.be/F3HpRuUW2A8?si=D6U-FiYumNaiHOKH";
    return {
      method: "Sprinkler Irrigation",
      image: "images/spri.jpg",
      video: videoUrl,
      telugu: videoUrl,
      english: videoUrl,
    };
  } else if (name.includes("center") || name.includes("pivot")) {
    const videoUrl = "https://www.youtube.com/embed/HvvNvFXZu8k";
    return {
      method: "Center Pivot Irrigation",
      image: "images/center.jpg",
      video: videoUrl,
      telugu: videoUrl,
      english: videoUrl,
    };
  } else if (
    name.includes("surface") ||
    name.includes("paddy") ||
    name.includes("awd") ||
    name.includes("flood")
  ) {
    const videoUrl = "https://youtube.com/shorts/9JamSTrI5es?si=mKQrgkjhoD3QZ9za";
    return {
      method: "Surface Irrigation",
      image: "images/surface.jpg",
      video: videoUrl,
      telugu: videoUrl,
      english: videoUrl,
    };
  } else {
    const videoUrl = "https://youtu.be/d5GPzKER5yw";
    return {
      method: "Drip Irrigation",
      image: "images/drip.jpg",
      video: videoUrl,
      telugu: videoUrl,
      english: videoUrl,
    };
  }
}

// Protected recommendation endpoint: Unauthorized users are blocked
app.post("/suggest", requireUserAuth, ensureDb, async (req, res) => {
  try {
    const { crop, soil, water, area } = req.body;

    if (
      typeof crop !== "string" ||
      typeof soil !== "string" ||
      typeof water !== "string" ||
      !crop.trim() ||
      !soil.trim() ||
      !water.trim()
    ) {
      return res.status(400).json({
        message: "Please provide crop, soil, and water.",
      });
    }

    const cropValue = crop.trim();
    const soilValue = soil.trim();
    const waterValue = water.trim();

    // 1. Exact match on crop, soil, and water
    let method = await Method.findOne({
      crop: { $regex: `^${escapeRegex(cropValue)}$`, $options: "i" },
      soil: { $regex: `^${escapeRegex(soilValue)}$`, $options: "i" },
      water: { $regex: `^${escapeRegex(waterValue)}$`, $options: "i" },
    }).lean();

    // 2. Fallback: match on crop and soil
    if (!method) {
      method = await Method.findOne({
        crop: { $regex: `^${escapeRegex(cropValue)}$`, $options: "i" },
        soil: { $regex: `^${escapeRegex(soilValue)}$`, $options: "i" },
      }).lean();
    }

    // 3. Fallback: match on crop
    if (!method) {
      method = await Method.findOne({
        crop: { $regex: `^${escapeRegex(cropValue)}$`, $options: "i" },
      }).lean();
    }

    // 4. Default fallback by crop type if not in DB
    if (!method) {
      let defaultMethodName = "Drip Irrigation";
      const cLower = cropValue.toLowerCase();
      if (cLower.includes("subsurface")) {
        defaultMethodName = "Subsurface Irrigation";
      } else if (cLower.includes("center") || cLower.includes("pivot")) {
        defaultMethodName = "Center Pivot Irrigation";
      } else if (
        cLower.includes("paddy") ||
        cLower.includes("surface") ||
        cLower.includes("flood")
      ) {
        defaultMethodName = "Surface Irrigation";
      } else if (cLower.includes("bajra") || cLower.includes("furrow")) {
        defaultMethodName = "Furrow Irrigation";
      } else if (
        cLower.includes("maize") ||
        cLower.includes("gram") ||
        cLower.includes("wheat") ||
        cLower.includes("sprinkler")
      ) {
        defaultMethodName = "Sprinkler Irrigation";
      } else if (
        cLower.includes("cotton") ||
        cLower.includes("chilli") ||
        cLower.includes("tomato") ||
        cLower.includes("drip")
      ) {
        defaultMethodName = "Drip Irrigation";
      }
      method = {
        crop: cropValue,
        soil: soilValue,
        water: waterValue,
        recommended_method: defaultMethodName,
        description: `Recommended irrigation method for ${cropValue}: ${defaultMethodName}.`,
      };
    }

    console.log(
      "Matched irrigation method:",
      method.recommended_method,
      "for crop:",
      cropValue,
      "user:",
      req.user ? req.user.username : "authenticated"
    );

    const media = getMethodMedia(method.recommended_method);
    const cleanImage =
      (method.image_url ? method.image_url.replace(/['"]/g, "").trim() : "") ||
      media.image;
    const finalTelugu = media.telugu;
    const finalEnglish = media.english;

    return res.status(200).json({
      method: method.recommended_method,
      description:
        method.description ||
        `Optimized ${method.recommended_method} for ${cropValue}.`,
      image: cleanImage,
      image_url: cleanImage,
      area: area || null,
      default_language: "telugu",
      video_url: finalTelugu,
      video_telugu: finalTelugu,
      video_english: finalEnglish,
      audio_tracks: [
        {
          id: "telugu",
          label: "Telugu",
          full_label: "Telugu (Default)",
          is_default: true,
          embed_url: finalTelugu,
        },
        {
          id: "english",
          label: "English",
          full_label: "English",
          is_default: false,
          embed_url: finalEnglish,
        },
      ],
      video: {
        url: finalTelugu,
        telugu_url: finalTelugu,
        english_url: finalEnglish,
        title: `${method.recommended_method} Video Guide`,
        source: method.video_source || "Agricultural Extension Service",
        description:
          method.video_description ||
          `Comprehensive guide on ${method.recommended_method}.`,
        local_url: method.local_video_url || "videos/sprinkler.mp4",
      },
    });
  } catch (error) {
    console.error("Suggestion Error:", error);

    return res.status(500).json({
      message: "Unable to read irrigation methods.",
      error: error.message,
    });
  }
});

// ==========================================
// GET REGISTERED USERS COUNT (ADMIN ONLY)
// ==========================================

app.get("/users/count", requireAdminAuth, ensureDb, async (req, res) => {
  try {
    const count = await User.countDocuments();

    return res.status(200).json({
      count,
    });
  } catch (error) {
    console.error("Count Users Error:", error);

    return res.status(500).json({
      message: "Server error while fetching user count.",
    });
  }
});

// ==========================================
// GET ALL REGISTERED USERS (ADMIN ONLY)
// ==========================================

app.get("/admin/users", requireAdminAuth, ensureDb, async (req, res) => {
  try {
    const users = await User.find({}, "-password").sort({ createdAt: -1 }).lean();

    const usersWithCounts = await Promise.all(
      users.map(async (u) => {
        const orConditions = [{ userId: u._id }];
        if (u.username) {
          orConditions.push({ username: new RegExp(`^${escapeRegex(u.username)}$`, "i") });
          orConditions.push({ name: new RegExp(`^${escapeRegex(u.username)}$`, "i") });
        }
        if (u.email) {
          orConditions.push({ email: new RegExp(`^${escapeRegex(u.email)}$`, "i") });
        }
        const feedbackCount = await Feedback.countDocuments({ $or: orConditions });

        return {
          _id: u._id,
          username: u.username,
          email: u.email || (u.username.includes("@") ? u.username : ""),
          createdAt: u.createdAt,
          feedbackCount,
        };
      })
    );

    return res.status(200).json(usersWithCounts);
  } catch (error) {
    console.error("Get Admin Users Error:", error);

    return res.status(500).json({
      message: "Server error while fetching registered users.",
    });
  }
});

// ==========================================
// GET SPECIFIC USER'S FEEDBACK (ADMIN ONLY)
// ==========================================

app.get("/admin/users/:id/feedback", requireAdminAuth, ensureDb, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({
        message: "Invalid user ID.",
      });
    }

    const user = await User.findById(req.params.id, "-password").lean();
    if (!user) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    const orConditions = [{ userId: user._id }];
    if (user.username) {
      orConditions.push({ username: new RegExp(`^${escapeRegex(user.username)}$`, "i") });
      orConditions.push({ name: new RegExp(`^${escapeRegex(user.username)}$`, "i") });
    }
    if (user.email) {
      orConditions.push({ email: new RegExp(`^${escapeRegex(user.email)}$`, "i") });
    }

    const feedbacks = await Feedback.find({ $or: orConditions })
      .sort({ createdAt: -1 })
      .lean();

    return res.status(200).json({
      user: {
        _id: user._id,
        username: user.username,
        email: user.email || (user.username.includes("@") ? user.username : ""),
        createdAt: user.createdAt,
      },
      feedbacks,
    });
  } catch (error) {
    console.error("Get User Feedback Error:", error);

    return res.status(500).json({
      message: "Server error while fetching user feedback.",
    });
  }
});

// ==========================================
// SUBMIT FEEDBACK
// ==========================================

app.post("/api/feedback", ensureDb, async (req, res) => {
  try {
    const { name, email, rating, like, improve, comments, userId, username } = req.body;
    const authUser = getAuthenticatedUser(req);
    const finalUserId = userId || (authUser ? authUser.userId : null);
    const finalUsername = username || (authUser ? authUser.username : "");
    const finalEmail = email || (authUser ? authUser.email : "");
    const finalName = name || (authUser ? authUser.username : "Anonymous");

    const feedback = await Feedback.create({
      userId: finalUserId,
      username: finalUsername,
      name: finalName,
      email: finalEmail,
      rating: Number(rating) || 5,
      like: like || "",
      improve: improve || "",
      comments: comments || "",
    });

    return res.status(201).json({
      message: "Feedback submitted successfully!",
      id: feedback._id,
    });
  } catch (error) {
    console.error("Feedback Error:", error);

    return res.status(500).json({
      message: "Server error while submitting feedback.",
    });
  }
});

// ==========================================
// GET ALL FEEDBACK (ADMIN ONLY)
// ==========================================

app.get("/feedbacks", requireAdminAuth, ensureDb, async (req, res) => {
  try {
    const feedbacks = await Feedback.find()
      .sort({ createdAt: -1 })
      .lean();

    return res.status(200).json(feedbacks);
  } catch (error) {
    console.error("Fetch Feedback Error:", error);

    return res.status(500).json({
      message: "Server error while fetching feedbacks.",
    });
  }
});

// ==========================================
// DELETE FEEDBACK (ADMIN ONLY)
// ==========================================

app.delete("/feedbacks/:id", requireAdminAuth, ensureDb, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({
        message: "Invalid feedback ID.",
      });
    }

    const result = await Feedback.findByIdAndDelete(req.params.id);

    if (!result) {
      return res.status(404).json({
        message: "Feedback not found.",
      });
    }

    return res.status(200).json({
      message: "Feedback deleted.",
    });
  } catch (error) {
    console.error("Delete Feedback Error:", error);

    return res.status(500).json({
      message: "Server error while deleting feedback.",
    });
  }
});

// ==========================================
// HEALTH CHECK ENDPOINT (DIAGNOSTICS & MONITORING)
// ==========================================

app.get("/api/health", async (req, res) => {
  let dbStatus = "disconnected";
  let dbError = null;

  try {
    await connectToDatabase();
    dbStatus = mongoose.connection.readyState === 1 ? "connected" : "connecting";
  } catch (err) {
    dbStatus = "error";
    dbError = err.message;
  }

  return res.status(200).json({
    status: "ok",
    database: dbStatus,
    databaseName: mongoose.connection.name || null,
    databaseError: dbError,
    environment: {
      hasMongoUri: Boolean(process.env.MONGO_URI),
      hasAdminToken: Boolean(process.env.ADMIN_TOKEN),
      hasJwtSecret: Boolean(process.env.JWT_SECRET),
      nodeEnv: process.env.NODE_ENV || "development",
      port: process.env.PORT || 5000,
    },
    timestamp: new Date().toISOString(),
  });
});

// ==========================================
// PROTECTED PAGES & STATIC FILES ROUTING
// ==========================================

// Multi-path frontend folder resolution (works both in local dev and on Vercel)
const possibleFrontendPaths = [
  path.join(__dirname, "../frontend"),
  path.join(__dirname, "../../frontend"),
  path.join(process.cwd(), "CSP-Final_Project(A_17)/start/frontend"),
  path.join(process.cwd(), "start/frontend"),
  path.join(process.cwd(), "frontend"),
];
let frontendPath = path.join(__dirname, "../frontend");
for (const p of possibleFrontendPaths) {
  if (fs.existsSync(p)) {
    frontendPath = p;
    break;
  }
}

// Requirement 1: When a user opens http://localhost:5000, display the First page.
app.get("/", (req, res) => {
  return res.sendFile(path.join(frontendPath, "firstpage.html"));
});

// Requirement 5: Do not allow direct access to irrigation homepage without logging in.
app.get(["/main.html", "/main"], (req, res) => {
  const user = getAuthenticatedUser(req);
  if (user) {
    return res.sendFile(path.join(frontendPath, "main.html"));
  }
  return res.redirect("/login.html?unauthorized=1");
});

// Convenient aliases
app.get("/login", (req, res) => {
  return res.redirect("/login.html");
});

app.get("/register", (req, res) => {
  return res.redirect("/register.html");
});

// Serve frontend assets (CSS, JS, images, videos, public pages)
app.use(express.static(frontendPath));

// Fallback for any unknown route: redirect to first page
app.use((req, res) => {
  return res.redirect("/firstpage.html");
});

// ==========================================
// START SERVER AND CONNECT TO MONGODB (LOCAL)
// ==========================================

async function startServer() {
  try {
    await connectToDatabase();
    console.log("Database:", mongoose.connection.name);
    console.log("Collection:", Method.collection.name);
  } catch (error) {
    console.warn("Initial DB connection warning (will retry on incoming requests):", error.message);
  }

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

if (require.main === module) {
  startServer();
}

app.app = app;
module.exports = app;

module.exports.app = app;
module.exports.connectToDatabase = connectToDatabase;
module.exports.startServer = startServer;
module.exports.generateToken = generateToken;
module.exports.verifyToken = verifyToken;
module.exports.getAuthenticatedUser = getAuthenticatedUser;

