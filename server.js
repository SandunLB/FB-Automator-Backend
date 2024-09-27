const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();

// Updated CORS configuration
const corsOptions = {
  origin: [
    'http://localhost:3001',
    process.env.FRONTEND_URL,
    'chrome-extension://caadlncmmfcghiiehgcnkpjnlgafkjgh',
    'https://ikman.lk',
    'https://test-front-end-dfec6.web.app' // Add your frontend URL here
  ],
  optionsSuccessStatus: 200,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// Define schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  stripeCustomerId: { type: String, default: 'Not subscribed' },
  subscriptionId: { type: String, default: 'Not subscribed' },
  subscriptionStatus: { type: String, default: 'trial' },
  trialEndDate: { type: Date, required: true }
});

const carSchema = new mongoose.Schema({
  make: String,
  model: String,
  type: String,
  year: Number,
  mileage: Number,
  price: Number,
  bodyStyle: String,
  condition: String,
  fuelType: String,
  location: String,
  description: String,
  imageUrls: [String],
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

// Create models
const User = mongoose.model('User', userSchema);
const Car = mongoose.model('Car', carSchema);

// JWT secret keys
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader) return res.status(403).json({ error: 'No token provided' });

  const bearer = bearerHeader.split(' ');
  const token = bearer[1];

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Failed to authenticate token' });
    req.userId = decoded.id;
    next();
  });
};

// Middleware to check subscription status
const checkSubscription = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const now = new Date();
    if (user.subscriptionStatus === 'trial' && now > user.trialEndDate) {
      user.subscriptionStatus = 'expired';
      await user.save();
    }

    req.subscriptionStatus = user.subscriptionStatus;
    next();
  } catch (error) {
    res.status(500).json({ error: 'Failed to check subscription status' });
  }
};


app.get('/test', (req, res) => {
  res.json({ message: 'Test route is working!' });
});

app.get('/test-db', async (req, res) => {
  try {
    const count = await User.countDocuments();
    res.json({ message: 'Database connection successful', userCount: count });
  } catch (error) {
    res.status(500).json({ error: 'Database connection failed', details: error.message });
  }
});

app.get('/test-jwt', (req, res) => {
  try {
    const token = jwt.sign({ test: 'data' }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'JWT creation successful', token });
  } catch (error) {
    res.status(500).json({ error: 'JWT creation failed', details: error.message });
  }
});

app.get('/test-stripe', async (req, res) => {
  try {
    const paymentIntents = await stripe.paymentIntents.list({ limit: 1 });
    res.json({ message: 'Stripe connection successful', paymentIntentCount: paymentIntents.data.length });
  } catch (error) {
    res.status(500).json({ error: 'Stripe connection failed', details: error.message });
  }
});


// User registration
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const trialEndDate = new Date(Date.now() + 60 * 60 * 1000 * 24); // 24 hours from now
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      trialEndDate,
      subscriptionStatus: 'trial'
    });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully with 24-hour free trial' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// User login
app.post('/login', async (req, res) => {
  const { identifier, password } = req.body;

  try {
    const user = await User.findOne({ $or: [{ username: identifier }, { email: identifier }] });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id }, JWT_REFRESH_SECRET, { expiresIn: '7d' });

    res.json({ token, refreshToken, username: user.username });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Token refresh
app.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const newToken = jwt.sign({ id: decoded.id }, JWT_SECRET, { expiresIn: '15m' });
    res.json({ token: newToken });
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// Protected route to get cars
app.get('/cars', verifyToken, checkSubscription, async (req, res) => {
  try {
    const cars = await Car.find({ userId: req.userId });
    res.json({ cars, subscriptionStatus: req.subscriptionStatus });
  } catch (error) {
    console.error('Error fetching cars:', error);
    res.status(500).json({ error: 'Failed to fetch car data' });
  }
});

// Protected route to add a car
app.post('/cars', verifyToken, checkSubscription, async (req, res) => {
  const carData = { ...req.body, userId: req.userId };
  
  try {
    const newCar = new Car(carData);
    await newCar.save();
    res.status(201).json({ message: 'Car data added successfully', car: newCar, subscriptionStatus: req.subscriptionStatus });
  } catch (error) {
    console.error('Error saving to MongoDB:', error);
    res.status(500).json({ error: 'Failed to add car data' });
  }
});

// Protected route to delete a single car
app.delete('/cars/:id', verifyToken, checkSubscription, async (req, res) => {
  try {
    const car = await Car.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    if (!car) {
      return res.status(404).json({ error: 'Car not found or you do not have permission to delete it' });
    }
    res.json({ message: 'Car deleted successfully', subscriptionStatus: req.subscriptionStatus });
  } catch (error) {
    console.error('Error deleting car:', error);
    res.status(500).json({ error: 'Failed to delete car' });
  }
});

// Protected route to delete multiple cars
app.post('/cars/delete-multiple', verifyToken, checkSubscription, async (req, res) => {
  const { carIds } = req.body;

  if (!Array.isArray(carIds) || carIds.length === 0) {
    return res.status(400).json({ error: 'Invalid or empty car IDs array' });
  }

  try {
    const result = await Car.deleteMany({
      _id: { $in: carIds },
      userId: req.userId
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'No cars found or you do not have permission to delete them' });
    }

    res.json({ message: `${result.deletedCount} car(s) deleted successfully`, subscriptionStatus: req.subscriptionStatus });
  } catch (error) {
    console.error('Error deleting multiple cars:', error);
    res.status(500).json({ error: 'Failed to delete cars' });
  }
});

// Protected route to update a car's description
app.patch('/cars/:id', verifyToken, checkSubscription, async (req, res) => {
  const { id } = req.params;
  const { description } = req.body;

  try {
    const updatedCar = await Car.findOneAndUpdate(
      { _id: id, userId: req.userId },
      { description },
      { new: true }
    );

    if (!updatedCar) {
      return res.status(404).json({ error: 'Car not found or you do not have permission to update it' });
    }

    res.json({ message: 'Car description updated successfully', car: updatedCar, subscriptionStatus: req.subscriptionStatus });
  } catch (error) {
    console.error('Error updating car description:', error);
    res.status(500).json({ error: 'Failed to update car description' });
  }
});

// Create Stripe checkout session
app.post('/create-checkout-session', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [
        {
          price: process.env.STRIPE_PRICE_ID,
          quantity: 1,
        },
      ],
      success_url: `${process.env.BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancel`,
      client_reference_id: user._id.toString(),
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('Error creating checkout session:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Get subscription status
app.get('/subscription-status', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const now = new Date();
    if (user.subscriptionStatus === 'trial' && now > user.trialEndDate) {
      user.subscriptionStatus = 'expired';
      await user.save();
    }

    res.json({
      subscriptionStatus: user.subscriptionStatus,
      trialEndDate: user.trialEndDate,
      stripeCustomerId: user.stripeCustomerId,
      subscriptionId: user.subscriptionId
    });
  } catch (error) {
    console.error('Error fetching subscription status:', error);
    res.status(500).json({ error: 'Failed to fetch subscription status' });
  }
});

// Cancel subscription
app.post('/cancel-subscription', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || user.subscriptionId === 'Not subscribed') {
      return res.status(404).json({ error: 'User or subscription not found' });
    }

    const subscription = await stripe.subscriptions.update(user.subscriptionId, {
      cancel_at_period_end: true
    });

    user.subscriptionStatus = 'canceling';
    await user.save();

    res.json({ message: 'Subscription will be canceled at the end of the billing period' });
  } catch (error) {
    console.error('Error canceling subscription:', error);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

// Handle successful checkout
app.get('/success', async (req, res) => {
  const { session_id } = req.query;

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    const user = await User.findById(session.client_reference_id);

    if (user) {
      user.stripeCustomerId = session.customer;
      user.subscriptionId = session.subscription;
      user.subscriptionStatus = 'active';
      await user.save();
    }

    res.redirect(`${process.env.FRONTEND_URL}/subscription-success`);
  } catch (error) {
    console.error('Error handling successful checkout:', error);
    res.redirect(`${process.env.FRONTEND_URL}/subscription-error`);
  }
});

// Export the Express API
module.exports = app;