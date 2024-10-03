require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();

// CORS configuration
app.use(cors());

// Use JSON parsing middleware for all routes except the webhook route
app.use((req, res, next) => {
  if (req.path === '/api/stripe-webhook') {
    next();
  } else {
    express.json()(req, res, next);
  }
});

// Use raw body parsing for the Stripe webhook route
app.use('/api/stripe-webhook', express.raw({type: 'application/json'}));

// MongoDB connection
let cachedDb = null;
async function connectToDatabase() {
  if (cachedDb) {
    return cachedDb;
  }
  const db = await mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  cachedDb = db;
  return db;
}

// Define schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  stripeCustomerId: { type: String, default: 'Not subscribed' },
  subscriptionId: { type: String, default: 'Not subscribed' },
  subscriptionStatus: { type: String, default: 'trial' },
  cancelAtPeriodEnd: { type: Boolean, default: false },
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

// User registration
app.post('/api/register', async (req, res) => {
  await connectToDatabase();
  const { username, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const trialEndDate = new Date(Date.now() + 60 * 60 * 1000 * 24); // 24 hour from now
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      trialEndDate,
      subscriptionStatus: 'trial'
    });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully with 1-hour free trial' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  await connectToDatabase();
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
app.post('/api/refresh-token', async (req, res) => {
  await connectToDatabase();
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
app.get('/api/cars', verifyToken, checkSubscription, async (req, res) => {
  await connectToDatabase();
  try {
    const cars = await Car.find({ userId: req.userId });
    res.json({ cars, subscriptionStatus: req.subscriptionStatus });
  } catch (error) {
    console.error('Error fetching cars:', error);
    res.status(500).json({ error: 'Failed to fetch car data' });
  }
});

// Protected route to add a car
app.post('/api/cars', verifyToken, checkSubscription, async (req, res) => {
  await connectToDatabase();
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

// Protected route to delete cars (single or multiple)
app.delete('/api/cars/delete', verifyToken, checkSubscription, async (req, res) => {
  await connectToDatabase();
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
    console.error('Error deleting cars:', error);
    res.status(500).json({ error: 'Failed to delete cars' });
  }
});

// Protected route to update a car's description
app.patch('/api/cars/:id', verifyToken, checkSubscription, async (req, res) => {
  await connectToDatabase();
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

// Protected route to get user profile
app.get('/api/profile', verifyToken, async (req, res) => {
  await connectToDatabase();
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// Protected route to update username
app.patch('/api/update-username', verifyToken, async (req, res) => {
  await connectToDatabase();
  const { newUsername } = req.body;

  try {
    const existingUser = await User.findOne({ username: newUsername });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const user = await User.findByIdAndUpdate(
      req.userId,
      { username: newUsername },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'Username updated successfully', user });
  } catch (error) {
    console.error('Error updating username:', error);
    res.status(500).json({ error: 'Failed to update username' });
  }
});

// Protected route to update password
app.patch('/api/update-password', verifyToken, async (req, res) => {
  await connectToDatabase();
  const { currentPassword, newPassword } = req.body;

  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedNewPassword;
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).json({ error: 'Failed to update password' });
  }
});

// Create Stripe checkout session
app.post('/api/create-checkout-session', verifyToken, async (req, res) => {
  await connectToDatabase();
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
      success_url: `${process.env.BASE_URL}/api/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancel`,
      client_reference_id: user._id.toString(),
      subscription_data: {
        metadata: {
          userId: user._id.toString(),
        },
      },
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('Error creating checkout session:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Get subscription status
app.get('/api/subscription-status', verifyToken, async (req, res) => {
  await connectToDatabase();
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
      cancelAtPeriodEnd: user.cancelAtPeriodEnd,
      trialEndDate: user.trialEndDate,
      stripeCustomerId: user.stripeCustomerId,
      subscriptionId: user.subscriptionId
    });
  } catch (error) {
    console.error('Error fetching subscription status:', error);
    res.status(500).json({ error: 'Failed to fetch subscription status' });
  }
});

// Create Stripe Customer Portal session
app.post('/api/create-customer-portal-session', verifyToken, async (req, res) => {
  await connectToDatabase();
  try {
    const user = await User.findById(req.userId);
    if (!user || !user.stripeCustomerId) {
      return res.status(404).json({ error: 'User or Stripe customer not found' });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: `${process.env.FRONTEND_URL}/account`,
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('Error creating customer portal session:', error);
    res.status(500).json({ error: 'Failed to create customer portal session' });
  }
});

// Handle Stripe webhook
app.post('/api/stripe-webhook', async (req, res) => {
  await connectToDatabase();
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook Error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  switch (event.type) {
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted':
    case 'invoice.payment_succeeded':
    case 'invoice.payment_failed':
      const subscription = event.data.object;
      await handleSubscriptionChange(subscription);
      break;
    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.json({received: true});
});

// Handle subscription changes
async function handleSubscriptionChange(subscription) {
  const userId = subscription.metadata.userId;
  const user = await User.findById(userId);

  if (!user) {
    console.error(`User not found for subscription ${subscription.id}`);
    return;
  }

  user.subscriptionId = subscription.id;
  user.stripeCustomerId = subscription.customer;
  user.cancelAtPeriodEnd = subscription.cancel_at_period_end;

  switch (subscription.status) {
    case 'active':
      user.subscriptionStatus = subscription.cancel_at_period_end ? 'active_canceling' : 'active';
      break;
    case 'past_due':
      user.subscriptionStatus = 'past_due';
      break;
    case 'unpaid':
      user.subscriptionStatus = 'unpaid';
      break;
    case 'canceled':
      user.subscriptionStatus = 'canceled';
      break;
    default:
      user.subscriptionStatus = subscription.status;
  }

  await user.save();
}

// Handle successful checkout
app.get('/api/success', async (req, res) => {
  await connectToDatabase();
  const { session_id } = req.query;

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    const user = await User.findById(session.client_reference_id);

    if (user) {
      user.stripeCustomerId = session.customer;
      user.subscriptionId = session.subscription;
      user.subscriptionStatus = 'active';
      user.cancelAtPeriodEnd = false;
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