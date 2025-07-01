const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const blogRoutes = require('../routes/blogs');
const categoryRoutes = require('../routes/categories');
const authRoutes = require('../routes/auth');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
app.use(bodyParser.json());
app.use(cors());

// MongoDB connection
console.log('MONGO_URI:', process.env.MONGO_URI); // Log the MongoDB URI for debugging

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error: ', err));

// Use routes for blogs and categories
app.use('/api/blogs', blogRoutes);
app.use('/api/categories', categoryRoutes);
app.use('/api/auth', authRoutes); 

// Test route
app.get('/test', (req, res) => {
  res.send('The API is working fine!');
});

// Export the Express app for Vercel serverless function
// module.exports = { app };
module.exports = (req, res) => {
  app(req, res); // Forward the request and response to the Express app
};

// If running locally, start the server on port 5000
// if (process.env.NODE_ENV !== 'production') {
//   const PORT = process.env.PORT || 5000;
//   app.listen(PORT, () => {
//     console.log(`Server running on port ${PORT}`);
//   });
// }
