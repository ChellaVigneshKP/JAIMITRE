require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { OpenAI } = require('openai');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
});

const FLASK_API_URL = process.env.FLASK_API_URL || 'http://localhost:5000';
async function getResponse(prompt) {
    try {
        const response = await openai.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{ role: 'user', content: prompt }],
            max_tokens: 150,
        });
        return response.choices[0].message.content.trim();
    } catch (error) {
        console.error('Error from OpenAI API:', error);
        throw new Error('Failed to get response from OpenAI API');
    }
}

// Route to get MITRE info
app.post('/api/get-mitre-info', async (req, res) => {
    const { query } = req.body;
    try {
        const flaskResponse = await axios.get(`${FLASK_API_URL}/attack-id/${encodeURIComponent(query)}`);
        const mitreInfo = flaskResponse.data;
        res.json({ reply: mitreInfo });
    } catch (error) {
        console.error('Error fetching MITRE info:', error);
        res.status(500).json({ reply: 'An error occurred.' });
    }
});

app.post('/api/get-d3fend-info', async (req, res) => {
    const { query } = req.body;
    try {
        const prompt = `Describe a defensive technique from the D3FEND framework related to: ${query}`;
        const reply = await getResponse(prompt);
        res.json({ reply });
    } catch (error) {
        console.error('Error fetching D3FEND info:', error);
        res.status(500).json({ reply: 'An error occurred.' });
    }
});

// Route to get response from the model
app.post('/api/get-response', async (req, res) => {
    const { prompt } = req.body;
    try {
        const reply = await getResponse(prompt);
        res.json({ response: reply });
    } catch (error) {
        console.error('Error fetching model response:', error);
        res.status(500).json({ response: 'An error occurred.' });
    }
});

app.listen(4000, () => {
    console.log('Server is running on port 4000');
});
