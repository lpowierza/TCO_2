import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import { google } from "googleapis";
import cookieParser from "cookie-parser";
import admin from "firebase-admin";
import { getFirestore } from "firebase-admin/firestore";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import firebaseConfig from "./firebase-applet-config.json" with { type: "json" };

// Initialize Firebase Admin
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      projectId: firebaseConfig.projectId,
    });
  } catch (e) {
    console.warn("Firebase Admin failed to initialize automatically. Admin features might be limited.");
  }
}

async function startServer() {
  const app = express();
  app.set("trust proxy", 1);
  const PORT = 3000;

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://apis.google.com",
          "https://www.gstatic.com",
          "https://www.googleapis.com",
          "https://*.firebaseapp.com"
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://fonts.gstatic.com"
        ],
        imgSrc: ["'self'", "data:", "https:", "blob:", "https://www.gstatic.com", "https://*.googleapis.com"],
        connectSrc: [
          "'self'",
          "https://*.googleapis.com",
          "https://*.firebaseapp.com",
          "https://*.firebase.com",
          "https://identitytoolkit.googleapis.com",
          "wss://*.firebaseio.com",
          "https://*.firebaseio.com"
        ],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        frameAncestors: ["*"],
        frameSrc: [
          "'self'",
          "https://*.firebaseapp.com",
          "https://apis.google.com"
        ],
        objectSrc: ["'none'"],
      }
    },
    crossOriginEmbedderPolicy: false,
    frameguard: false
  }));

  app.use(express.json());
  app.use(cookieParser());

  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Zbyt wiele żądań. Spróbuj ponownie za 15 minut.' }
  });

  const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Zbyt wiele żądań do panelu admina.' }
  });

  const sheetsLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 30,
    message: { error: 'Zbyt wiele żądań do arkusza.' }
  });

  app.use('/api/', generalLimiter);
  app.use('/api/admin/', adminLimiter);
  app.use('/api/sheets/', sheetsLimiter);

  // Helper to verify admin
  const verifyAdmin = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const idToken = req.headers.authorization?.split("Bearer ")[1];
    if (!idToken) {
      console.warn("verifyAdmin: Missing Authorization header");
      return res.status(401).json({ error: "Brak tokena uwierzytelniającego" });
    }

    try {
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      if (decodedToken.email === "leszek.powierza@gmail.com") {
        (req as any).user = decodedToken;
        next();
      } else {
        console.warn(`verifyAdmin: Access denied for email ${decodedToken.email}`);
        res.status(403).json({ error: "Brak uprawnień administratora" });
      }
    } catch (error: any) {
      console.error("verifyAdmin: Token verification failed", error.message);
      res.status(401).json({ error: "Nieprawidłowy lub wygasły token" });
    }
  };

  // Admin: List all users from Firebase Auth
  app.get("/api/admin/users", verifyAdmin, async (req, res) => {
    try {
      console.log("Admin: Fetching users list...");
      let allUsers: any[] = [];
      let nextPageToken;

      try {
        do {
          const listUsersResult: admin.auth.ListUsersResult = await admin.auth().listUsers(1000, nextPageToken);
          const users = listUsersResult.users.map(u => ({
            id: u.uid,
            email: u.email || "",
            displayName: u.displayName || "",
            lastLogin: u.metadata.lastSignInTime ? { toDate: () => new Date(u.metadata.lastSignInTime!) } : null,
            createdAt: u.metadata.creationTime,
            providers: u.providerData.map(p => p.providerId)
          }));
          allUsers = allUsers.concat(users);
          nextPageToken = listUsersResult.pageToken;
        } while (nextPageToken);

        console.log(`Admin: Found ${allUsers.length} users in Firebase Auth. Providers:`, 
          allUsers.reduce((acc, u) => {
            u.providers.forEach((p: string) => acc[p] = (acc[p] || 0) + 1);
            return acc;
          }, {} as Record<string, number>)
        );
      } catch (authError: any) {
        console.warn("Firebase Auth listUsers failed (Identity Toolkit API might be disabled). Falling back to Firestore users list.", authError.message);
        
        try {
          const defaultApp = admin.apps[0];
          const dbAdmin = firebaseConfig.firestoreDatabaseId 
            ? getFirestore(defaultApp, firebaseConfig.firestoreDatabaseId) 
            : getFirestore(defaultApp);
          const usersSnap = await dbAdmin.collection('users').get();
          allUsers = usersSnap.docs.map(doc => {
            const data = doc.data();
            return {
              id: doc.id,
              email: data.email || "",
              displayName: data.displayName || "",
              lastLogin: data.lastLogin || null,
              createdAt: data.createdAt || null,
              providers: data.providers || []
            };
          });
          console.log(`Admin Fallback: Found ${allUsers.length} users in Firestore.`);
        } catch (dbError: any) {
          console.error("Admin Fallback: Firestore fetch failed as well", dbError);
          allUsers = [];
        }
      }

      res.json(allUsers);
    } catch (error: any) {
      console.error("Critical error in /api/admin/users:", error);
      res.json([]);
    }
  });

  // Admin: Reset password (send link)
  app.post("/api/admin/reset-password", verifyAdmin, async (req, res) => {
    const { uid, newPassword } = req.body;
    console.log(`Admin: Request to change password for UID: ${uid}`);
    
    if (!uid) {
      return res.status(400).json({ error: "Brak UID użytkownika" });
    }
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: "Brak nowego hasła lub jest za krótkie" });
    }

    try {
      await admin.auth().updateUser(uid, {
        password: newPassword,
      });
      console.log(`Admin: Password changed successfully for ${uid}`);
      res.json({ success: true });
    } catch (error: any) {
      console.error("Error updating password in Firebase Admin:", error);
      const isDev = process.env.NODE_ENV !== 'production';
      res.status(500).json({ 
        error: "Błąd podczas zmiany hasła w systemie Auth",
        ...(isDev ? { details: error.message } : {})
      });
    }
  });

  // Proxy endpoint for Gemini API
  app.post("/api/gemini", verifyAdmin, async (req, res) => {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: "Brak konfiguracji klucza Gemini" });
    }
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(req.body),
        }
      );
      const data = await response.json();
      res.json(data);
    } catch (error: any) {
      const isDev = process.env.NODE_ENV !== 'production';
      res.status(500).json({
        error: "Błąd podczas komunikacji z Gemini API",
        ...(isDev ? { details: error.message } : {})
      });
    }
  });

  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    // Redirect URI will be set per request
  );

  const SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly"];

  // Helper to get actual origin
  const getOrigin = (req: express.Request) => {
    return `${req.protocol}://${req.get("host")}`;
  };

  // 1. Get OAuth URL
  app.get("/api/auth/google/url", (req, res) => {
    const origin = getOrigin(req);
    const redirectUri = `${origin}/api/auth/google/callback`;
    
    const url = oauth2Client.generateAuthUrl({
      access_type: "offline",
      scope: SCOPES,
      redirect_uri: redirectUri,
      prompt: "consent",
    });
    res.json({ url });
  });

  // 2. OAuth Callback
  app.get("/api/auth/google/callback", async (req, res) => {
    const { code } = req.query;
    const origin = getOrigin(req);
    const redirectUri = `${origin}/api/auth/google/callback`;

    try {
      const { tokens } = await oauth2Client.getToken({
        code: code as string,
        redirect_uri: redirectUri,
      });

      // Store tokens in a secure cookie
      res.cookie("google_tokens", JSON.stringify(tokens), {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: "strict",
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/api',
      });

      const safeOrigin = process.env.ALLOWED_ORIGIN || 'https://tco-bay.vercel.app';

      res.send(`
        <html>
          <body>
            <script>
              if (window.opener) {
                window.opener.postMessage({ type: 'GOOGLE_OAUTH_SUCCESS' }, '${safeOrigin}');
                window.close();
              } else {
                window.location.href = '/';
              }
            </script>
            <p>Uwierzytelnienie zakończone sukcesem. To okno zamknie się automatycznie.</p>
          </body>
        </html>
      `);
    } catch (error) {
      console.error("Błąd wymiany kodu:", error);
      res.status(500).send("Błąd uwierzytelniania");
    }
  });

  // 3. Fetch Public Sheets Data
  app.get("/api/sheets/data", async (req, res) => {
    const apiKey = process.env.GOOGLE_API_KEY;
    const spreadsheetId = process.env.GOOGLE_SPREADSHEET_ID || "1HpOpTwhYoZjUDCohZPQd7Qeha9w3XGiVDSB7pzEbNco";
    
    const ALLOWED_RANGES = [
      "'Laptopy - Cennik'!B:J",
      "Apple!B:J"
    ];
    const requestedRange = req.query.range as string;
    const range = ALLOWED_RANGES.includes(requestedRange)
      ? requestedRange
      : (process.env.GOOGLE_SHEETS_RANGE || ALLOWED_RANGES[0]);

    if (!apiKey) {
      return res.status(401).json({ error: "Brak skonfigurowanego klucza API Google (GOOGLE_API_KEY)" });
    }

    try {
      const sheets = google.sheets({ version: "v4", auth: apiKey });
      const response = await sheets.spreadsheets.values.get({
        spreadsheetId,
        range,
      });

      res.json({ values: response.data.values });
    } catch (error: any) {
      console.error("Błąd pobierania danych z arkusza:", error);
      res.status(500).json({ error: "Błąd pobierania danych z Google Sheets. Upewnij się, że arkusz jest publiczny i nazwa zakładki jest poprawna." });
    }
  });

  // 4. Logout from Google
  app.post("/api/auth/google/logout", (req, res) => {
    res.clearCookie("google_tokens", {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: "strict",
      path: '/api',
    });
    res.json({ success: true });
  });

  // 5. Check Auth Status
  app.get("/api/auth/google/status", (req, res) => {
    res.json({ isAuthenticated: !!req.cookies.google_tokens });
  });

  // Helper to verify any signed in user
  const verifyUser = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const idToken = req.headers.authorization?.split("Bearer ")[1];
    if (!idToken) {
      return res.status(401).json({ error: "Brak tokena uwierzytelniającego" });
    }

    try {
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      (req as any).user = decodedToken;
      next();
    } catch (error: any) {
      console.error("verifyUser: Token verification failed", error.message);
      res.status(401).json({ error: "Nieprawidłowy lub wygasły token" });
    }
  };

  // User: Self delete account (along with all database data)
  app.post("/api/user/delete-account", verifyUser, async (req, res) => {
    const uid = (req as any).user.uid;
    console.log(`Request to delete account for UID: ${uid}`);
    try {
      const defaultApp = admin.apps[0];
      const dbAdmin = firebaseConfig.firestoreDatabaseId 
        ? getFirestore(defaultApp, firebaseConfig.firestoreDatabaseId) 
        : getFirestore(defaultApp);

      // 1. Delete user's comparisons
      const compSnapshot = await dbAdmin.collection("comparisons").where("userId", "==", uid).get();
      const batch = dbAdmin.batch();
      compSnapshot.docs.forEach((doc) => {
        batch.delete(doc.ref);
      });
      
      // 2. Delete user's profile doc in 'users'
      const userDocRef = dbAdmin.collection("users").doc(uid);
      batch.delete(userDocRef);

      // Commit firestore edits
      await batch.commit();
      console.log(`Firestore data for user ${uid} deleted successfully.`);

      // 3. Delete from Firebase Auth
      await admin.auth().deleteUser(uid);
      console.log(`Auth user ${uid} deleted successfully.`);

      res.json({ success: true });
    } catch (error: any) {
      console.error(`Error deleting account for user ${uid}:`, error);
      res.status(500).json({ 
        error: "Wystąpił błąd podczas usuwania konta z bazy danych lub systemu Auth",
        details: error.message || String(error)
      });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Serwer działa na http://localhost:${PORT}`);
  });
}

startServer();
