// Event listener for sending a message to the AI model
document.getElementById('send-button').addEventListener('click', async () => {
    const userInput = document.getElementById('user-input').value;
    if (!userInput) return;

    // Add user message to chat window
    appendMessage('User', userInput);

    // Call backend to get response from AI model at port 3000
    try {
        const response = await getModelResponse(userInput);
        appendMessage('Bot', response);
    } catch (error) {
        console.error('Error fetching model response:', error);
        appendMessage('Bot', 'Sorry, there was an error.');
    }

    // Clear the input field
    document.getElementById('user-input').value = '';
});

// Event listener for fetching MITRE info
document.getElementById('get-mitre-info-button').addEventListener('click', async () => {
    const mitreQuery = document.getElementById('mitre-query').value;
    const apiEndpoint = document.getElementById('api-endpoint').value;

    if (!mitreQuery || !apiEndpoint) {
        console.error('Missing MITRE query or endpoint');
        return;
    }

    // Construct endpoint with query parameter
    const fullEndpoint = `${apiEndpoint}/${mitreQuery}`;
    console.log(`Fetching MITRE info from ${fullEndpoint} with query: ${mitreQuery}`);

    try {
        const response = await fetchFromAPI('http://localhost:5000', fullEndpoint, mitreQuery);
        appendMessage('MITRE Info', response);
    } catch (error) {
        console.error('Error fetching MITRE info:', error);
        appendMessage('MITRE Info', 'Sorry, there was an error.');
    }
});


// Event listener for fetching D3FEND info
document.getElementById('get-d3fend-info-button').addEventListener('click', async () => {
    const d3fendQuery = document.getElementById('d3fend-query').value;

    if (!d3fendQuery) {
        console.error('Missing D3FEND query');
        return;
    }

    // Log the API call details
    console.log(`Fetching D3FEND info with query: ${d3fendQuery}`);

    // Call Python server at port 5000 for D3FEND info
    try {
        const response = await fetchFromAPI('http://localhost:5000', '/get-d3fend-info', d3fendQuery);
        appendMessage('D3FEND Info', response);
    } catch (error) {
        console.error('Error fetching D3FEND info:', error);
        appendMessage('D3FEND Info', 'Sorry, there was an error.');
    }
});

// Function to fetch model response from the Node server at port 3000
async function getModelResponse(input) {
    try {
        const response = await fetch('http://localhost:3000/api/get-response', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ prompt: input }),
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        return data.response; // Adjust based on the server's response field
    } catch (error) {
        console.error('Error in getModelResponse:', error);
        return 'Sorry, there was an error.';
    }
}

// Function to fetch data from the Python server at port 5000 for MITRE/D3FEND info
async function fetchFromAPI(baseURL, endpoint, query) {
    try {
        // Properly concatenate the URL
        const url = `${baseURL}${endpoint}`;
        console.log(`Fetching from URL: ${url} with query: ${JSON.stringify({ query })}`);
        
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ query }), // Send query as payload
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        return data.reply || data; // Adjust based on the server's response
    } catch (error) {
        console.error('Error in fetchFromAPI:', error);
        return 'Sorry, there was an error.';
    }
}


// Function to append messages to the chat window
function appendMessage(sender, text) {
    const chatWindow = document.getElementById('chat-window');
    const messageDiv = document.createElement('div');
    messageDiv.classList.add('message');
    messageDiv.innerHTML = `<strong>${sender}:</strong> ${text}`;
    chatWindow.appendChild(messageDiv);
    chatWindow.scrollTop = chatWindow.scrollHeight;  // Scroll to bottom
}
