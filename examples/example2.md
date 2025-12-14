import express from 'express';
import { secure } from 'zsecure-express';

const app = express();

app.use(secure({
// Core security
helmet: true,
cors: {
origin: ['https://myapp.com'],
credentials: true
},
rateLimit: {
windowMs: 15 _ 60 _ 1000,
max: 100
},

// Advanced protection
honeypot: {
enabled: true,
level: 'aggressive'
},
threatIntel: {
enabled: true,
providers: ['abuseipdb', 'virustotal']
},

// Monitoring
logging: {
level: 'detailed',
audit: true
}
}));

// Your routes...
