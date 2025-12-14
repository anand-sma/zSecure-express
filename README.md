# 🛡️ zSecure-Express - Ultimate Security for Node.js

[![npm version](https://img.shields.io/npm/v/zsecure-express)](https://www.npmjs.com/package/zsecure-express)
[![security](https://img.shields.io/badge/security-enterprise-blue)](https://zsecure.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**One-line security for your Express apps. Enterprise-grade protection made simple.**

## ✨ Features

✅ **23+ Security Layers** - More than any other package  
✅ **Auto Honeypot** - Deceptive security that catches hackers  
✅ **Threat Intelligence** - Real-time IP reputation checks  
✅ **AI Anomaly Detection** - Machine learning powered protection  
✅ **Zero Configuration** - Works out of the box  
✅ **TypeScript Ready** - Full TypeScript support  
✅ **Production Ready** - Battle-tested in enterprise

## 🚀 Installation

```bash
npm install zsecure-express express
# or
yarn add zsecure-express express
```

# ⚡ 5-Second Setup

import express from 'express';
import { secure } from 'zsecure-express';

const app = express();

// One line = Full security 🎉
app.use(secure());

app.get('/', (req, res) => {
res.json({ message: 'I am secure!' });
});

app.listen(3000);

# 🎯 Advanced Usage

## Preset Configurations

import { secure } from 'zsecure-express';

## Choose from 6 presets

app.use(secure.preset('enterprise')); // Maximum security
app.use(secure.preset('api')); // API-focused
app.use(secure.preset('honeypot')); // Deception-focused
app.use(secure.preset('ecommerce')); // PCI-compliant

# Custom Configuration

app.use(secure({
rateLimit: { max: 1000 },
honeypot: { enabled: true },
threatIntel: { providers: ['abuseipdb'] }
}));

# Individual Middleware

import { helmet, rateLimit, honeywall } from 'zsecure-express';

app.use(helmet());
app.use(rateLimit());
app.use(honeywall({ level: 'aggressive' }));

# 🔧 Configuration Options

Option Type Default Description
helmet boolean/object true Advanced security headers
rateLimit boolean/object true Smart rate limiting
honeypot boolean/object false Deceptive endpoints
threatIntel boolean/object false IP reputation checks
anomalyDetection boolean/object false ML-powered detection
logging.audit boolean false Security audit logs

# 📊 Monitoring

import { securityMetrics } from 'zsecure-express';

// Get real-time security metrics
app.get('/security/metrics', (req, res) => {
res.json(securityMetrics.get());
});

// View honeypot interactions
app.get('/security/honeypot', (req, res) => {
res.json(honeywall.getInteractions());
});

# 📄 License

MIT © ZSecure Team

# ⚠️ Disclaimer

This package provides security layers but doesn't guarantee complete protection. Always follow security best practices.
