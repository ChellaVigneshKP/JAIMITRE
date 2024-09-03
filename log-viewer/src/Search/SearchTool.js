import React, { useState , useContext} from 'react';
import axios from 'axios';
import './SearchTool.css';
import {ButtonContext} from "../ButtonContext"

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
  const handleAttckSearch = () => {
    const message = `ATT&CK Search Term: ${attckSearchTerm}, Filter: ${attckDropdownValue}`;
    console.log(message);
    setButtonMessage(message);
    setButtonMessage({ role: 'system-assistant', content: message });
  };
  const handleD3fendSearch = () => {
    console.log(`D3FEND Search Term: ${d3fendSearchTerm}, Filter: ${d3fendDropdownValue}`);
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
            <option value="filter1">Filter 1</option>
            <option value="filter2">Filter 2</option>
            {/* Add more options as needed */}
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
            <option value="filter1">Filter 1</option>
            <option value="filter2">Filter 2</option>
            {/* Add more options as needed */}
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
