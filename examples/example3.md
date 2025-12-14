import express from 'express';
import {
helmet,
rateLimit,
csrf,
honeywall,
encryption
} from 'zsecure-express';

const app = express();

// Pick and choose what you need
app.use(helmet());
app.use(rateLimit());
app.use(csrf());
app.use(honeywall());

// Use utilities
const { hashPassword, verifyPassword } = encryption;
const hashed = await hashPassword('mypassword');
