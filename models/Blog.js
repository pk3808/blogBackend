const mongoose = require('mongoose');

// Define the Blog schema
const BlogSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Category',  // Ref to Category model
    required: true,
  },
  // Store media as an array of objects (for multiple files)
  mediaUrls: [{  // Array to store media details (filename, type, Buffer)
    filename: { type: String },
    fileType: { type: String },
    fileData: { type: Buffer },  // Store the media as a Buffer (binary data)
  }],
  date: {
    type: Date,
    default: Date.now,
  },
});

// Export the Blog model
module.exports = mongoose.model('Blog', BlogSchema);
