const express = require('express');
const Category = require('../models/Category');
const router = express.Router();

// Get all categories
router.get('/', async (req, res) => {
  try {
    const categories = await Category.find();
    res.json(categories);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// get category by ID

router.get('/:id', async (req, res) => {
try {
  const cateogary = await Category.findById(req.params.id);
  if (!cateogary) {
    return res.status(404).send('Category not found');
  }
  res.json(cateogary);
} catch (error) {
  res.status(500).send(error.message);
  }

  });


// Create new category
router.post('/', async (req, res) => {
  const { name, description } = req.body;
  try {
    const newCategory = new Category({ name, description });
    await newCategory.save();
    res.status(201).json(newCategory);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

module.exports = router;
