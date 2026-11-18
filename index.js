require('dotenv').config();
if (!process.env.VERCEL) require('dns').setServers(['8.8.8.8', '8.8.4.4']); // CHANGED
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const port = process.env.PORT || 5000;

// ---- Fail early with a clear message if .env is not filled in ----
if (!process.env.MONGODB_URI) {
  console.error('Missing MONGODB_URI in .env');
  process.exit(1);
}
if (!process.env.JWT_SECRET) {
  console.error('Missing JWT_SECRET in .env');
  process.exit(1);
}

const app = express();

// CLIENT_URL may be a single url or comma separated list (no trailing slash needed)
const allowedOrigins = [
  'http://localhost:3000',
  ...(process.env.CLIENT_URL || '').split(',').map((u) => u.trim().replace(/\/$/, '')),
].filter(Boolean);

app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json());

// ---- JWT verification middleware ----
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ message: 'Unauthorized access: No token provided' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send({ message: 'Forbidden access: Invalid token' });
    }
    req.user = decoded;
    next();
  });
};

const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const sendError = (res, error) => res.status(500).send({ message: error.message });

async function run() {
  await client.connect();
  const db = client.db('bookNookDB');
  const booksCollection = db.collection('books');
  const borrowsCollection = db.collection('borrows');
  const usersCollection = db.collection('user'); // created by BetterAuth

  // Health check
  app.get('/', (req, res) => {
    res.send('BookNook Server is Running!');
  });

  // JWT: only registered users (BetterAuth "user" collection) get a token
  app.post('/jwt', async (req, res) => {
    try {
      const email = req.body?.email;
      if (!email || typeof email !== 'string') {
        return res.status(400).send({ message: 'Email is required for JWT' });
      }
      const exists = await usersCollection.findOne({ email: email.toLowerCase() });
      if (!exists) {
        return res.status(404).send({ message: 'No registered user with this email' });
      }
      const token = jwt.sign({ email: exists.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
      res.send({ token });
    } catch (error) {
      sendError(res, error);
    }
  });

  // ---------------- BOOKS ----------------

  // 1. GET /books — all books (public). Optional ?limit=6 and ?email=
  app.get('/books', async (req, res) => {
    try {
      const limit = Math.max(parseInt(req.query.limit) || 0, 0);
      const email = req.query.email;
      const query = email ? { userEmail: email } : {};

      let cursor = booksCollection.find(query).sort({ addedDate: -1 });
      if (limit > 0) cursor = cursor.limit(limit);
      res.send(await cursor.toArray());
    } catch (error) {
      sendError(res, error);
    }
  });

  // 2. GET /books/:id — one book (login required)
  app.get('/books/:id', verifyToken, async (req, res) => {
    try {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: 'Invalid Book ID' });
      }
      const result = await booksCollection.findOne({ _id: new ObjectId(id) });
      if (!result) {
        return res.status(404).send({ message: 'Book not found' });
      }
      res.send(result);
    } catch (error) {
      sendError(res, error);
    }
  });

  // 3. POST /books — add a book (owner = logged in user)
  app.post('/books', verifyToken, async (req, res) => {
    try {
      const b = req.body || {};
      if (!b.title || !b.author || !b.category || !b.image || !b.description) {
        return res.status(400).send({ message: 'Title, author, category, image and description are required' });
      }
      const newBook = {
        title: b.title,
        author: b.author,
        category: b.category,
        image: b.image,
        description: b.description,
        totalCopies: Math.max(parseInt(b.totalCopies) || 1, 0),
        userName: b.userName,
        userEmail: req.user.email, // from the token, not from the body
        addedDate: new Date().toISOString(),
      };
      const result = await booksCollection.insertOne(newBook);
      res.send(result);
    } catch (error) {
      sendError(res, error);
    }
  });

  // 4. PATCH /books/:id — update own book
  app.patch('/books/:id', verifyToken, async (req, res) => {
    try {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: 'Invalid Book ID' });
      }

      const book = await booksCollection.findOne({ _id: new ObjectId(id) });
      if (!book) return res.status(404).send({ message: 'Book not found' });
      if (book.userEmail !== req.user.email) {
        return res.status(403).send({ message: 'You can only edit your own books' });
      }

      const allowed = ['title', 'author', 'category', 'image', 'description', 'totalCopies'];
      const updatedData = {};
      for (const key of allowed) {
        if (req.body[key] !== undefined) updatedData[key] = req.body[key];
      }
      if (updatedData.totalCopies !== undefined) {
        const copies = parseInt(updatedData.totalCopies);
        if (Number.isNaN(copies) || copies < 0) {
          return res.status(400).send({ message: 'totalCopies must be 0 or more' });
        }
        updatedData.totalCopies = copies;
      }
      if (Object.keys(updatedData).length === 0) {
        return res.status(400).send({ message: 'Nothing to update' });
      }

      const result = await booksCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updatedData }
      );
      res.send(result);
    } catch (error) {
      sendError(res, error);
    }
  });

  // 5. DELETE /books/:id — delete own book
  app.delete('/books/:id', verifyToken, async (req, res) => {
    try {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: 'Invalid Book ID' });
      }

      const book = await booksCollection.findOne({ _id: new ObjectId(id) });
      if (!book) return res.status(404).send({ message: 'Book not found' });
      if (book.userEmail !== req.user.email) {
        return res.status(403).send({ message: 'You can only delete your own books' });
      }

      const result = await booksCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    } catch (error) {
      sendError(res, error);
    }
  });

  // ---------------- BORROWS ----------------

  // 6. POST /borrows — borrow a book
  app.post('/borrows', verifyToken, async (req, res) => {
    try {
      const { bookId, bookTitle, bookImage, borrowDate, returnDate } = req.body || {};
      const userEmail = req.user.email; // from the token

      if (!bookId || !ObjectId.isValid(bookId)) {
        return res.status(400).send({ message: 'Invalid Book ID' });
      }

      // No double borrow
      const existingBorrow = await borrowsCollection.findOne({ bookId, userEmail });
      if (existingBorrow) {
        return res.status(400).send({ message: 'You have already borrowed this book!' });
      }

      // Atomically take one copy (only if at least one is left)
      const updated = await booksCollection.findOneAndUpdate(
        { _id: new ObjectId(bookId), totalCopies: { $gt: 0 } },
        { $inc: { totalCopies: -1 } }
      );
      if (!updated) {
        return res.status(400).send({ message: 'Sorry, no copies are currently available!' });
      }

      try {
        const insertResult = await borrowsCollection.insertOne({
          bookId,
          bookTitle,
          bookImage,
          userEmail,
          borrowDate,
          returnDate,
        });
        res.send(insertResult);
      } catch (insertError) {
        // Put the copy back if saving the borrow failed
        await booksCollection.updateOne({ _id: new ObjectId(bookId) }, { $inc: { totalCopies: 1 } });
        throw insertError;
      }
    } catch (error) {
      sendError(res, error);
    }
  });

  // 7. GET /borrows?email= — borrows of the logged in user
  app.get('/borrows', verifyToken, async (req, res) => {
    try {
      const email = req.query.email;
      if (!email || req.user.email !== email) {
        return res.status(403).send({ message: 'Forbidden access' });
      }
      res.send(await borrowsCollection.find({ userEmail: email }).toArray());
    } catch (error) {
      sendError(res, error);
    }
  });

  // 8. DELETE /borrows/:id — return a book
  app.delete('/borrows/:id', verifyToken, async (req, res) => {
    try {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: 'Invalid Borrow ID' });
      }

      const borrowItem = await borrowsCollection.findOne({ _id: new ObjectId(id) });
      if (!borrowItem) {
        return res.status(404).send({ message: 'Borrow record not found' });
      }
      if (borrowItem.userEmail !== req.user.email) {
        return res.status(403).send({ message: 'Forbidden access' });
      }

      const deleteResult = await borrowsCollection.deleteOne({ _id: new ObjectId(id) });

      if (borrowItem.bookId && ObjectId.isValid(borrowItem.bookId)) {
        await booksCollection.updateOne(
          { _id: new ObjectId(borrowItem.bookId) },
          { $inc: { totalCopies: 1 } }
        );
      }
      res.send(deleteResult);
    } catch (error) {
      sendError(res, error);
    }
  });

  // 404 + error handler (must be after the routes)
  app.use((req, res) => {
    res.status(404).send({ message: 'Route not found' });
  });
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send({ message: 'Something went wrong on the server' });
  });

  // CHANGED: only listen on a port when running locally (Vercel does not need it)
  if (!process.env.VERCEL) {
    app.listen(port, () => {
      console.log(`BookNook MongoDB connected! Server listening on port ${port}`);
    });
  }
}

// CHANGED: export a handler so Vercel can run the app
const ready = run().catch((err) => {
  console.error('MongoDB Connection Error:', err.message);
  if (!process.env.VERCEL) process.exit(1);
});

module.exports = async (req, res) => {
  await ready;
  return app(req, res);
};