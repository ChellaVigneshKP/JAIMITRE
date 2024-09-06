import React, { useState, useContext } from 'react';
import axios from 'axios';
import './SearchTool.css';
import { ButtonContext } from "../ButtonContext";

const SearchTool = () => {
  const [attckSearchTerm, setAttckSearchTerm] = useState('');
  const [d3fendSearchTerm, setD3fendSearchTerm] = useState('');
  const [attckDropdownValue, setAttckDropdownValue] = useState('');
  const [d3fendDropdownValue, setD3fendDropdownValue] = useState('');
  const [file, setFile] = useState(null);
  const [url, setUrl] = useState('');
  const [fileResponse, setFileResponse] = useState(null);
  const [urlResponse, setUrlResponse] = useState(null);
  const { setButtonMessage } = useContext(ButtonContext);
  const [attckResults, setAttckResults] = useState(null);

  const handleAttckSearch = async () => {
    try {
      let response;
      if (attckDropdownValue === 'content') {
        response = await axios.post('http://localhost:5000/search-content', {
          content: attckSearchTerm,
        });
        if (response.data && response.data.length > 0) {
          const formattedMessage = response.data.map((item) => (
            `Name: ${item.name}\nID: ${item.id}\nDescription: ${item.description}\n`
          )).join('\n');
          setButtonMessage({ role: 'system-assistant', content: formattedMessage });
        } else {
          setButtonMessage({ role: 'system-assistant', content: 'No similar results found.' });
        }
        console.log(attckResults);
      } else if (attckDropdownValue === 'filter2') {
        response = await axios.post('http://localhost:5000/search-attackid', {
          ids: [attckSearchTerm],  // Assuming attckSearchTerm is an ID
      });
      if(response.data && response.data.length > 0){
        const formattedMessage = response.data.map((item) => (
          `ATT&CK ID : ${item.attack_id}\nName: ${item.name}\nID: ${item.id}\nDescription: ${item.description}\n`
        )).join('\n');
        setButtonMessage({ role: 'system-assistant', content: formattedMessage });
      }else{
        setButtonMessage({ role: 'system-assistant', content: 'No matching techniques found.' });
      }
      setAttckResults(response.data);
      }

      if (response) {
        setAttckResults(response.data);
      }
    } catch (error) {
      console.error('Error fetching ATT&CK techniques:', error);
      setAttckResults({ error: 'Error fetching data' });
    }
  };

  const handleD3fendSearch = async () => {
    try {
      let response;
      if (d3fendDropdownValue === 'name') {
        response = await axios.post('http://localhost:5000/search-d3fendname', {
          name: d3fendSearchTerm,
        });
      } else if (d3fendDropdownValue === 'id') {
        response = await axios.post('http://localhost:5000/search-d3fendid', {
          id: d3fendSearchTerm,
        });
      }

      if (response.data && !response.data.error) {
        const formattedMessage = `Name: ${response.data.technique_name}\nD3FEND Extraction:\n${JSON.stringify(response.data.api_response, null, 2)}`;
        console.log(response.data)
        setButtonMessage({ role: 'system-assistant', content: formattedMessage });
      } else {
        setButtonMessage({ role: 'system-assistant', content: 'No results found or an error occurred.' });
      }
    } catch (error) {
      console.error('Error fetching D3FEND data:', error);
      setButtonMessage({ role: 'system-assistant', content: 'Error fetching D3FEND data.' });
    }
  };

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleFileUpload = async () => {
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post('http://localhost:4000/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setFileResponse(response.data);
      const { fileName, fileHash, mitreAttck } = response.data;
      const mitreAttckString = mitreAttck ? mitreAttck.join(', ') : 'N/A';
      const message = `File Name: ${fileName}\nFile Hash: ${fileHash}\nMITRE ATT&CK: ${mitreAttckString}`;
      setButtonMessage({ role: 'system', content: message });
    } catch (error) {
      console.error('Error uploading file:', error);
      setFileResponse({ error: 'Error uploading file' });
    }
  };

  const handleUrlChange = (e) => {
    setUrl(e.target.value);
  };

  const handleUrlSubmit = async () => {
    try {
      const response = await axios.post('http://localhost:4000/domaincheck', { url });
      const { domain, isSafe } = response.data;
      const safetyMessage = isSafe ? `${domain} is safe` : `${domain} is not safe`;
      setUrlResponse({ safetyMessage });
      setButtonMessage({ role: 'system', content: safetyMessage });
    } catch (error) {
      console.error('Error checking URL:', error);
      setUrlResponse({ safetyMessage: 'Error checking URL' });
    }
  };

  return (
    <div className="search-tool">
      <div className="section">
        <label htmlFor="attck-dropdown">ATT&CK Search</label>
        <div className="input-container">
          <select
            id="attck-dropdown"
            value={attckDropdownValue}
            onChange={(e) => setAttckDropdownValue(e.target.value)}
          >
            <option value="">Select Filter</option>
            <option value="content">Search by Content</option>
            <option value="filter2">Search by ID</option>
          </select>
          <input
            type="text"
            value={attckSearchTerm}
            onChange={(e) => setAttckSearchTerm(e.target.value)}
            placeholder="Search ATT&CK"
          />
          <button onClick={handleAttckSearch}>Search ATT&CK</button>
        </div>
      </div>

      <div className="section">
        <label htmlFor="d3fend-dropdown">D3FEND Search</label>
        <div className="input-container">
          <select
            id="d3fend-dropdown"
            value={d3fendDropdownValue}
            onChange={(e) => setD3fendDropdownValue(e.target.value)}
          >
            <option value="">Select Filter</option>
            <option value="id">Search By ID</option>
            <option value="name">Search By Name</option>
          </select>
          <input
            type="text"
            value={d3fendSearchTerm}
            onChange={(e) => setD3fendSearchTerm(e.target.value)}
            placeholder="Search D3FEND"
          />
          <button onClick={handleD3fendSearch}>Search D3FEND</button>
        </div>
      </div>

      <h3>File/URL Integrity Check</h3>
      <div className="integrity-check-section">
        <div className="integrity-check-container">
          <div className="integrity-input">
            <label htmlFor="file-upload">Upload File</label>
            <input
              id="file-upload"
              type="file"
              onChange={handleFileChange}
            />
            <button onClick={handleFileUpload}>Upload File</button>
            {fileResponse && (
              <div className="response">
                <h4>File Upload Response:</h4>
                {fileResponse.error ? (
                  <p>{fileResponse.error}</p>
                ) : (
                  <>
                    <p>File Name: {fileResponse.fileName}</p>
                    <p>File Hash: {fileResponse.fileHash}</p>
                    <h4>Mitre ATT&CK IDs:</h4>
                    <p>{fileResponse.mitreAttck.join(', ')}</p>
                  </>
                )}
              </div>
            )}
          </div>

          <div className="integrity-input">
            <label htmlFor="url-input">Check URL</label>
            <input
              id="url-input"
              type="text"
              value={url}
              onChange={handleUrlChange}
              placeholder="Enter URL"
            />
            <button onClick={handleUrlSubmit}>Check URL</button>
            {urlResponse && (
              <div className="response">
                <h4>URL Check Response:</h4>
                <p>{urlResponse.safetyMessage}</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SearchTool;
