import express from 'express';
import { secure } from 'zsecure-express';

const app = express();

// Use enterprise preset
app.use(secure.preset('enterprise'));

// Add custom API security
app.use('/api', secure({
rateLimit: { max: 1000 },
requestValidation: true,
sqlInjection: { level: 'strict' }
}));

// Admin panel with extra protection
app.use('/admin', secure({
rateLimit: { max: 50 },
require2FA: true,
honeywall: { level: 'paranoid' }
}));
