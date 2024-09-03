const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { OpenAI } = require('openai');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
require('dotenv').config();
const axios = require('axios');
const app = express();
const PORT = 4000;
const BING_SEARCH_API_KEY = process.env.BING_API_KEY1;
const BING_SEARCH_ENDPOINT = 'https://api.bing.microsoft.com/v7.0/search';
app.use(cors());
app.use(bodyParser.json());
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Set up multer for file upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage });
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }
  const filePath = path.join(__dirname, 'uploads', req.file.filename);
  const hash = crypto.createHash('sha256');
  const fileStream = fs.createReadStream(filePath);
  fileStream.on('data', (chunk) => hash.update(chunk));
  fileStream.on('end', async () => {
    const fileHash = hash.digest('hex');
    const options = {
      method: 'GET',
      url: `https://www.virustotal.com/api/v3/files/${fileHash}/behaviour_mitre_trees`,
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY,
        'accept': 'application/json'
      }
    };

    try {
      const virusTotalResponse = await axios.request(options);
      const virusReport = virusTotalResponse.data;
      const mitreIds = [];
      if (virusReport.data && virusReport.data['CAPE Sandbox']) {
        const tactics = virusReport.data['CAPE Sandbox'].tactics;
        tactics.forEach(tactic => {
          if (tactic.id) {
            mitreIds.push(tactic.id);
          } else {
            mitreIds.push('N/A');
          }

          tactic.techniques.forEach(technique => {
            if (technique.id) {
              mitreIds.push(technique.id);
            } else {
              mitreIds.push('N/A');
            }
          });
        });
      }
      res.json({
        fileName: req.file.filename,
        fileHash,
        mitreAttck: mitreIds
      });
    } catch (error) {
      console.error('Error with VirusTotal API:', error.message);
      res.status(500).json({ message: 'Error fetching VirusTotal report', error: error.message });
    }
  });

  fileStream.on('error', (err) => {
    res.status(500).send(`Error reading file: ${err.message}`);
  });
});

app.post('/process-file-from-uploads', (req, res) => {
  const { fileName } = req.body;
  if (!fileName) {
    return res.status(400).json({ message: 'No file name provided.' });
  }
  const filePath = path.join(__dirname, 'uploads', fileName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ message: 'File not found.' });
  }
  const hash = crypto.createHash('sha256');
  const fileStream = fs.createReadStream(filePath);
  fileStream.on('data', (chunk) => hash.update(chunk));
  fileStream.on('end', async () => {
    const fileHash = hash.digest('hex');
    const options = {
      method: 'GET',
      url: `https://www.virustotal.com/api/v3/files/${fileHash}/behaviour_mitre_trees`,
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY,
        'accept': 'application/json'
      }
    };

    try {
      const virusTotalResponse = await axios.request(options);
      const virusReport = virusTotalResponse.data;
      const mitreIds = [];

      if (virusReport.data && virusReport.data['CAPE Sandbox']) {
        const tactics = virusReport.data['CAPE Sandbox'].tactics;
        tactics.forEach(tactic => {
          if (tactic.id) {
            mitreIds.push(tactic.id);
          } else {
            mitreIds.push('N/A');
          }

          tactic.techniques.forEach(technique => {
            if (technique.id) {
              mitreIds.push(technique.id);
            } else {
              mitreIds.push('N/A');
            }
          });
        });
      }

      res.json({
        fileName,
        fileHash,
        mitreAttck: mitreIds
      });
    } catch (error) {
      console.error('Error with VirusTotal API:', error.message);
      res.status(500).json({ message: 'Error fetching VirusTotal report', error: error.message });
    }
  });

  fileStream.on('error', (err) => {
    res.status(500).json({ message: `Error reading file: ${err.message}` });
  });
});


const THRESHOLD = 0;

app.post('/domaincheck', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).send('No URL provided.');
  }

  const formattedUrl = url.replace(/^(?:https?:\/\/)/, '');
  const options = {
    method: 'GET',
    url: `https://www.virustotal.com/api/v3/domains/${formattedUrl}`,
    headers: {
      accept: 'application/json',
      'x-apikey': process.env.VIRUSTOTAL_API_KEY
    }
  };

  try {
    const virusTotalResponse = await axios.request(options);
    const virusReport = virusTotalResponse.data;
    const positives = virusReport.data.attributes.last_analysis_stats.malicious;
    const isSafe = positives <= THRESHOLD;
    res.json({
      domain: formattedUrl,
      isSafe,
      total: virusReport.data.attributes.last_analysis_stats.total
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching VirusTotal report', error: error.message });
  }
});

let conversationHistory = [];

const mapRole = (role) => {
  switch (role) {
    case 'system-assistant':
      return 'system';
    case 'assistant':
    case 'user':
    case 'system':
    default:
      return role;
  }
};

app.post('/chat', async (req, res) => {
  const { conversation } = req.body;
  const userMessage = conversation[conversation.length - 1].content;

  try {
    const bingResponse = await axios.get(BING_SEARCH_ENDPOINT, {
      headers: {
        'Ocp-Apim-Subscription-Key': BING_SEARCH_API_KEY,
      },
      params: {
        q: userMessage,
        count: 5,
      },
    });

    const searchResults = bingResponse.data.webPages.value;
    const resultsSummary = searchResults.map(result => ({
      name: result.name,
      url: result.url,
    }));
    conversationHistory.push({
      userMessage,
      searchResults: resultsSummary,
    });
    const chatPrompt = `User asked: ${userMessage}. Here are the search results: ${JSON.stringify(resultsSummary)}. Please provide a response.`;
    const messagesForOpenAI = conversation.map(msg => ({
      role: mapRole(msg.role),
      content: msg.content
    }));
    messagesForOpenAI.push({
      role: 'system',
      content: `Search results: ${JSON.stringify(resultsSummary)}`
    });
    messagesForOpenAI.push({
      role: 'user',
      content: userMessage
    });
    const chatResponse = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: messagesForOpenAI,
    });

    const reply = chatResponse.choices[0].message.content;
    res.json({
      reply,
      references: resultsSummary,
      searchCount: searchResults.length,
    });
  } catch (error) {
    console.error('Error with OpenAI API or Bing Search API:', error.message);
    res.status(500).json({ reply: 'Sorry, there was an error processing your request.' });
  }
});

app.post('/details', (req, res) => {
  const { index } = req.body;
  if (index < 0 || index >= conversationHistory.length) {
    return res.status(400).send('Invalid index.');
  }
  const conversationItem = conversationHistory[index];
  res.json(conversationItem);
});


if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
