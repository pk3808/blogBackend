const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { promisify } = require("util");

const mkdir = promisify(fs.mkdir);
const uploadDir = "uploads/";

const ensureDirectoryExistence = async (dir) => {
  try {
    await fs.promises.access(dir);
  } catch (error) {
    await mkdir(dir, { recursive: true });
  }
};

const generateFileName = () => {
  const timestamp = Date.now().toString(36); 
  const randomStr = crypto.randomBytes(3).toString('hex');
  const fileName = (timestamp + randomStr).slice(0, 6).toUpperCase();
  return fileName;
};

const storage = multer.diskStorage({
  destination: async function (req, file, cb) {
    await ensureDirectoryExistence(uploadDir);
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueFileName = generateFileName() + path.extname(file.originalname);
    cb(null, uniqueFileName);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ["image/jpeg", "image/png", "image/gif", "application/pdf"];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Invalid file type. Only images and PDFs are allowed!"), false);
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, 
  fileFilter: fileFilter,
});

module.exports = upload;