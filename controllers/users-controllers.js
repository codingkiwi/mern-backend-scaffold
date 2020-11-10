const HttpError = require('../models/http-error');
const { v4: uuidv4 } = require('uuid');
const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('../models/user');

const getUsers = async (req, res, next) => {
	let users;

	try {
		users = await User.find({}, '-password');
	} catch (err) {
		const error = new HttpError(
			'Fetching users failed, please try again later',
			500
		);
		return next(error);
	}

	res.json({ users: users.map((user) => user.toObject({ getters: true })) });
};

const createUser = async (req, res, next) => {
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		console.log(errors);
		return next(
			new HttpError('Invalid inputs passed, please check your data', 422)
		);
	}

	const { name, email, password } = req.body;

	let existingUser;

	try {
		existingUser = await User.findOne({ email: email });
	} catch (err) {
		const error = new HttpError('an error ocurred during signup', 500);
		return next(error);
	}

	if (existingUser) {
		const error = new HttpError(
			'A user with this email already exists, please login instead.',
			422
		);
		return next(error);
	}

	let hashedPassword;
	try {
		hashedPassword = await bcrypt.hash(password, 12);
	} catch (err) {
		const error = new HttpError(
			'Could not create user, please try again',
			500
		);
		return next(error);
	}

	const createdUser = new User({
		name,
		email,
		password: hashedPassword,
		image: req.file.path,
		places: [],
	});

	try {
		await createdUser.save();
	} catch (err) {
		const error = new HttpError(
			'Creating user failed please try again',
			500
		);
		return next(error);
	}

	let token;
	try {
		token = jwt.sign(
			{ userId: createdUser.id, email: createdUser.email },
			process.env.JWT_TOKEN_KEY,
			{ expiresIn: '1hr' }
		);
	} catch (err) {
		const error = new HttpError(
			'Creating user failed please try again',
			500
		);
		return next(error);
	}

	res.status(201).json({
		userId: createdUser.id,
		email: createdUser.email,
		token: token,
	});
};

const logInUser = async (req, res, next) => {
	const { email, password } = req.body;

	try {
		existingUser = await User.findOne({ email: email });
	} catch (err) {
		const error = new HttpError('an error ocurred during login', 500);
		return next(error);
	}

	if (!existingUser) {
		const error = new HttpError(
			'Invalid credentials, could not log you in',
			401
		);
		return next(error);
	}

	let isValidPassword = false;
	try {
		isValidPassword = await bcrypt.compare(password, existingUser.password);
	} catch (err) {
		const error = new HttpError(
			'Invalid credentials, could not log you in',
			500
		);
		return next(error);
	}

	if (!isValidPassword) {
		const error = new HttpError(
			'Invalid credentials, could not log you in',
			403
		);
		return next(error);
	}

	let token;
	try {
		token = jwt.sign(
			{ userId: existingUser.id, email: existingUser.email },
			process.env.JWT_TOKEN_KEY,
			{ expiresIn: '1hr' }
		);
	} catch (err) {
		const error = new HttpError(
			'Error logging in, please try again later',
			500
		);
		return next(error);
	}

	res.status(201).json({
		userId: existingUser.id,
		email: existingUser.email,
		token: token,
	});
};

exports.getUsers = getUsers;
exports.createUser = createUser;
exports.logInUser = logInUser;
