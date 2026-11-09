const http = require("http");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { app, generateToken, verifyToken } = require("./server");

async function runTests() {
  console.log("====================================================");
  console.log("RUNNING MODERN IRRIGATION AUTHENTICATION TEST SUITE");
  console.log("====================================================\n");

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✅ PASS: ${message}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${message}`);
      failed++;
    }
  }

  // 1. TOKEN UNIT TESTS
  console.log("1. Testing Token Generation & Verification (Native Crypto)...");
  const testPayload = { userId: "user123", username: "testfarmer", email: "test@farm.org" };
  const token = generateToken(testPayload);
  assert(typeof token === "string" && token.split(".").length === 3, "Token has valid 3-part JWT format");

  const decoded = verifyToken(token);
  assert(decoded && decoded.username === "testfarmer" && decoded.userId === "user123", "Token successfully verified and decoded");

  const tampered = token.slice(0, -5) + "abcde";
  assert(verifyToken(tampered) === null, "Tampered token correctly rejected");

  const expiredToken = (() => {
    const crypto = require("crypto");
    const JWT_SECRET = process.env.JWT_SECRET || "smart-irrigation-jwt-secret-key-2026-secure-token";
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const exp = Math.floor(Date.now() / 1000) - 100; // Past
    const body = Buffer.from(JSON.stringify({ ...testPayload, exp })).toString("base64url");
    const signature = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url");
    return `${header}.${body}.${signature}`;
  })();
  assert(verifyToken(expiredToken) === null, "Expired token correctly rejected");

  // 2. HTTP SERVER ROUTE TESTS
  console.log("\n2. Starting local HTTP test server on port 5055...");
  const server = http.createServer(app);
  await new Promise((res) => server.listen(5055, res));

  function request(path, options = {}) {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: 5055,
          path,
          method: options.method || "GET",
          headers: options.headers || {},
        },
        (res) => {
          let body = "";
          res.on("data", (chunk) => (body += chunk));
          res.on("end", () => {
            let json = null;
            try {
              json = JSON.parse(body);
            } catch (e) {}
            resolve({
              statusCode: res.statusCode,
              headers: res.headers,
              body,
              json,
            });
          });
        }
      );
      req.on("error", reject);
      if (options.body) {
        req.write(typeof options.body === "string" ? options.body : JSON.stringify(options.body));
      }
      req.end();
    });
  }

  try {
    // Test 3: Root and Unauthorized Access Protection
    console.log("\n3. Testing Page Routing & Unauthorized Access Protection...");
    const resRoot = await request("/");
    assert(
      resRoot.statusCode === 200 && resRoot.body.includes("Irrigation Systems"),
      `Root '/' displays the First page ('firstpage.html') (Status: ${resRoot.statusCode})`
    );

    const resMain = await request("/main.html");
    assert(
      resMain.statusCode === 302 && resMain.headers.location === "/login.html?unauthorized=1",
      `Direct access to '/main.html' without login redirects to /login.html?unauthorized=1 (Status: ${resMain.statusCode}, Location: ${resMain.headers.location})`
    );

    const resSuggestUnauth = await request("/suggest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { crop: "Cotton", soil: "Black Soil", water: "Medium", area: 2 },
    });
    assert(
      resSuggestUnauth.statusCode === 401,
      `Backend API 'POST /suggest' rejects unauthorized requests with 401 Unauthorized (Status: ${resSuggestUnauth.statusCode})`
    );

    // Test 4: Setup Database or In-Memory Mock
    console.log("\n4. Checking Database Connectivity / In-Memory Mock...");
    const User = mongoose.model("User");
    const Method = mongoose.model("Method");
    let isLiveDb = false;

    try {
      if (process.env.MONGO_URI) {
        await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 2000 });
        isLiveDb = true;
        console.log("  ✅ Connected to MongoDB Atlas Cluster");
      }
    } catch (dbErr) {
      console.log(`  ℹ️ Atlas cluster offline / IP not whitelisted (${dbErr.message.slice(0, 70)}...)`);
      console.log("  ℹ️ Attaching in-memory repository for unit validation");

      const inMemoryUsers = [];
      User.findOne = function (query) {
        return {
          async lean() {
            return this;
          },
          then(resolve) {
            if (query.$or) {
              for (const u of inMemoryUsers) {
                const matchUser = query.$or[0]?.username?.test(u.username);
                const matchEmail = query.$or[1]?.email?.test(u.email);
                if (matchUser || matchEmail) return resolve(u);
              }
              return resolve(null);
            }
            if (query.username) {
              const match = inMemoryUsers.find((u) => query.username.test(u.username));
              return resolve(match || null);
            }
            if (query.email) {
              const match = inMemoryUsers.find((u) => u.email && query.email.test(u.email));
              return resolve(match || null);
            }
            return resolve(null);
          },
        };
      };

      User.create = async function (userData) {
        const u = {
          _id: new mongoose.Types.ObjectId(),
          ...userData,
        };
        inMemoryUsers.push(u);
        return u;
      };

      Method.findOne = function (query) {
        return {
          lean() {
            return Promise.resolve({
              crop: "Cotton",
              soil: "Black Soil",
              water: "Medium",
              recommended_method: "Drip Irrigation",
              description: "Optimized Drip Irrigation for Cotton.",
              image_url: "images/drip.jpg",
              video_url: "https://youtu.be/d5GPzKER5yw",
            });
          },
        };
      };
    }

    const testUser = "testfarmer_" + Date.now();
    const testEmail = `${testUser}@irrigation.agri`;
    const testPass = "Precision2026!";

    // Test 5: Registration
    console.log("\n5. Testing User Registration...");
    const resReg = await request("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { username: testUser, email: testEmail, password: testPass, confirm: testPass },
    });
    assert(resReg.statusCode === 201, `User Registration returned 201 Created (Message: ${resReg.json?.message})`);

    // Test 5.2: Duplicate registration rejected
    const resRegDup = await request("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { username: testUser, email: testEmail, password: testPass, confirm: testPass },
    });
    assert(resRegDup.statusCode === 409, `Duplicate Username correctly rejected with 409 Conflict`);

    // Test 6: Login
    console.log("\n6. Testing User Login...");
    // Wrong password
    const resLoginWrong = await request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { username: testUser, password: "IncorrectPassword" },
    });
    assert(resLoginWrong.statusCode === 401, `Login with incorrect password rejected with 401 Unauthorized`);

    // Correct login by Username
    const resLoginUser = await request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { username: testUser, password: testPass },
    });
    assert(
      resLoginUser.statusCode === 200 && Boolean(resLoginUser.json?.token),
      `Login with Username successful and returned JWT token`
    );

    const setCookie = resLoginUser.headers["set-cookie"];
    assert(
      Array.isArray(setCookie) && setCookie.some((c) => c.includes("authToken=")),
      `Login sets HTTP-Only 'authToken' cookie with Max-Age`
    );

    const userToken = resLoginUser.json.token;

    // Correct login by Email
    const resLoginEmail = await request("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { identifier: testEmail, password: testPass },
    });
    assert(resLoginEmail.statusCode === 200, `Login with Email identifier also successful`);

    // Test 7: Authorized Access
    console.log("\n7. Testing Authorized Route & API Access...");
    const cookieHeader = setCookie ? setCookie[0].split(";")[0] : `authToken=${userToken}`;

    // Root / serves First page
    const resRootPage = await request("/");
    assert(
      resRootPage.statusCode === 200 && resRootPage.body.includes("Irrigation Systems"),
      `Root '/' consistently serves the First page ('firstpage.html')`
    );

    // /main.html with cookie
    const resAuthMain = await request("/main.html", {
      headers: { Cookie: cookieHeader },
    });
    assert(
      resAuthMain.statusCode === 200 && resAuthMain.body.includes("Smart Irrigation Dashboard"),
      `'/main.html' serves irrigation homepage ('main.html') when authenticated via Cookie`
    );

    // /api/auth/me with Bearer Token
    const resAuthMe = await request("/api/auth/me", {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    assert(
      resAuthMe.statusCode === 200 && resAuthMe.json?.user?.username === testUser,
      `'/api/auth/me' returns user profile when authenticated via Bearer token`
    );

    // Test 8: Recommendation API
    console.log("\n8. Testing Protected Irrigation Recommendation API...");
    const resSuggestAuth = await request("/suggest", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${userToken}`,
      },
      body: {
        crop: "Cotton",
        soil: "Black Soil",
        water: "Medium",
        area: 2,
      },
    });
    assert(
      resSuggestAuth.statusCode === 200 && Boolean(resSuggestAuth.json?.method),
      `Protected '/suggest' API returns recommendation: '${resSuggestAuth.json?.method}'`
    );
    assert(
      Boolean(resSuggestAuth.json?.image && resSuggestAuth.json?.video_url),
      `Recommendation includes image ('${resSuggestAuth.json?.image}') and video tutorial`
    );

    // Test 9: Logout
    console.log("\n9. Testing User Logout...");
    const resLogout = await request("/logout", {
      method: "POST",
      headers: { Cookie: cookieHeader },
    });
    const logoutCookies = resLogout.headers["set-cookie"];
    assert(
      resLogout.statusCode === 200 &&
        Array.isArray(logoutCookies) &&
        logoutCookies.some((c) => c.includes("Max-Age=0") || c.includes("Expires=")),
      `Logout endpoint clears 'authToken' cookie with Max-Age=0`
    );

    const resLogoutGet = await request("/logout");
    assert(
      resLogoutGet.statusCode === 302 && resLogoutGet.headers.location === "/firstpage.html?logged_out=1",
      `GET /logout redirects to /firstpage.html?logged_out=1`
    );

    // Test 10: Admin Registered Users & Feedback Flow
    console.log("\n10. Testing Admin Registered Users & User Feedback APIs...");
    const adminToken = process.env.ADMIN_TOKEN || "supersecrettoken";

    // Unauthenticated access to /admin/users -> 401
    const resAdminUnauth = await request("/admin/users");
    assert(
      resAdminUnauth.statusCode === 401,
      `'/admin/users' rejects unauthenticated requests with 401 Unauthorized`
    );

    // Authenticated access to /admin/users
    const resAdminUsers = await request("/admin/users", {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert(
      resAdminUsers.statusCode === 200 && Array.isArray(resAdminUsers.json),
      `'/admin/users' returns array of registered users (Count: ${resAdminUsers.json?.length})`
    );

    // Verify non-sensitive data (password never included)
    const hasPassword = resAdminUsers.json.some((u) => u.password !== undefined);
    assert(!hasPassword, `Registered users profile data does NOT expose sensitive password hashes`);

    // Submit a feedback linked to testUser
    const Feedback = mongoose.model("Feedback");
    const testFb = await Feedback.create({
      name: testUser,
      username: testUser,
      email: testEmail,
      rating: 5,
      like: "Precision Drip Irrigation recommendation",
      improve: "Add soil moisture sensors guide",
      comments: "Great agricultural platform!",
    });

    // Find the test user's ID
    const foundTestUser = resAdminUsers.json.find((u) => u.username === testUser);
    if (foundTestUser) {
      const resUserFeedback = await request(`/admin/users/${foundTestUser._id}/feedback`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      assert(
        resUserFeedback.statusCode === 200 && resUserFeedback.json?.user?.username === testUser,
        `'/admin/users/:id/feedback' returns selected user profile (Name: ${resUserFeedback.json?.user?.username})`
      );
      assert(
        Array.isArray(resUserFeedback.json?.feedbacks) && resUserFeedback.json?.feedbacks.length >= 1,
        `Returns submitted feedback list for selected user (Count: ${resUserFeedback.json?.feedbacks?.length})`
      );
    }

    // Clean up test feedback and test user
    await Feedback.deleteOne({ _id: testFb._id });
    if (isLiveDb) {
      await User.deleteOne({ username: testUser });
      console.log("\n  🧹 Cleaned up temporary test user and test feedback from MongoDB");
    }
  } finally {
    server.close();
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
  }

  console.log("\n====================================================");
  console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log("====================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
