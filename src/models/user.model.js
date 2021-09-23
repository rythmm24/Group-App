const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const { toJSON, paginate } = require('./plugins');
const { getAge, arrayLimit } = require('../validations/custom.validation');

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      validate(value) {
        if (!validator.isEmail(value)) {
          throw new Error('Invalid email');
        }
      },
    },
    profilePicture: {
      type: String,
      required: true,
    },
    birthDate: {
      type: Date,
      required: true,
      validate(value) {
        if (getAge(value) < 18) {
          throw new Error('Age must be greater than 18');
        }
      },
    },
    location: [
      {
        lat: String,
        long: String,
      },
    ],
    availableTime: [
      {
        startTime: Date,
        endTime: Date,
      },
    ],
    interestTags: {
      type: [
        {
          type: String,
        },
      ],
      default: [],
      validate: [arrayLimit, '{PATH} exceeds the limit of 5'],
    },
    weekDays: {
      type: [
        {
          type: String,
        },
      ],
      default: [],
    },
    aboutMe: {
      type: String,
      required: false,
      maxLength: 50,
    },
    isNewUser: {
      type: Boolean,
      default: true,
    },
    password: {
      type: String,
      required: true,
      trim: true,
      minLength: 8,
      validate(value) {
        if (!value.match(/\d/) || !value.match(/[a-zA-Z]/)) {
          throw new Error('Password must contain at least one letter and one number');
        }
      },
      private: true, // used by the toJSON plugin
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// add plugin that converts mongoose to json
userSchema.plugin(toJSON);
userSchema.plugin(paginate);

/**
 * Check if email is taken
 * @param {string} email - The user's email
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
userSchema.statics.isEmailTaken = async function (email, excludeUserId) {
  const user = await this.findOne({ email, _id: { $ne: excludeUserId } });
  return !!user;
};

/**
 * Check if password matches the user's password
 * @param {string} password
 * @returns {Promise<boolean>}
 */
userSchema.methods.isPasswordMatch = async function (password) {
  const user = this;
  return bcrypt.compare(password, user.password);
};

userSchema.pre('save', async function (next) {
  const user = this;
  if (user.isModified('password')) {
    user.password = await bcrypt.hash(user.password, 8);
  }
  next();
});

/**
 * @typedef User
 */
const User = mongoose.model('User', userSchema);

module.exports = User;
