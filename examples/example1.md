import express from 'express';
import { secure } from 'zsecure-express';

const app = express();

// Single line - full security
app.use(secure());

app.get('/', (req, res) => {
res.json({ message: 'Fully secured!' });
});

app.listen(3000);
