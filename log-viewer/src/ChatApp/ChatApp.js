import React, { useState, useContext, useEffect } from 'react';
import axios from 'axios';
import './ChatApp.css';
import { ButtonContext } from '../ButtonContext';

function ChatApp() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(null);
  const [currentReferences, setCurrentReferences] = useState([]);
  const { buttonMessage } = useContext(ButtonContext);

  useEffect(() => {
    if (buttonMessage) {
      setMessages((prevMessages) => [
        ...prevMessages,
        { role: buttonMessage.role, content: buttonMessage.content },
      ]);
    }
  }, [buttonMessage]);

  const sendMessage = async () => {
    if (input.trim() === '') return;

    const newMessage = { role: 'user', content: input };
    const updatedMessages = [...messages, newMessage];

    setMessages(updatedMessages);
    setLoading(true);

    try {
      const response = await axios.post('http://localhost:4000/chat', {
        conversation: updatedMessages,
      });

      const { reply, references, searchCount } = response.data;

      setMessages((prevMessages) => [
        ...prevMessages,
        {
          role: 'assistant',
          content: reply,
          references: references, // Add references to message
          searchCount: searchCount
        }
      ]);
    } catch (error) {
      console.error('Error fetching response from backend:', error);
      setMessages((prevMessages) => [
        ...prevMessages,
        { role: 'assistant', content: 'Error: Could not get a response.' },
      ]);
    } finally {
      setLoading(false);
      setInput('');
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    sendMessage();
  };

  const toggleDropdown = (index) => {
    setDropdownOpen(dropdownOpen === index ? null : index);
    setCurrentReferences(messages[index]?.references || []);
  };

  return (
    <div className="chat-container">
      <div className="chat-box">
        <div className="messages-container">
          {messages.map((msg, index) => (
            <div
              key={index}
              className={`message ${msg.role === 'user' ? 'user-message-container' : 
              msg.role === 'system' ? 'system-message-container' : 
              msg.role === 'system-assistant' ? 'system-assistant-message-container':'assistant-message-container'}`}>
              <div className={msg.role === 'user' ? 'user-message' : 
                msg.role === 'system' ? 'system-message' : 
                msg.role === 'system-assistant' ? 'system-assistant-message' : 'assistant-message'}>
                <div className="indicator">
                  {msg.role === 'user' ? 'You' : 
                  msg.role === 'system' ? 'System' : 
                  msg.role === 'system-assistant' ? 'System Assistant': 'MITRE Assistant'}
                </div>
                <div dangerouslySetInnerHTML={{ __html: msg.content }}></div>
                {msg.searchCount > 0 && (
                  <div>
                    <span onClick={() => toggleDropdown(index)}
                      className="search-info"
                      style={{ cursor: 'pointer', color: 'blue' }}>
                      Searched {msg.searchCount} sites {dropdownOpen === index ? '▲' : '▼'}
                    </span>
                    {dropdownOpen === index && (
                      <div className="references-dropdown">
                        <ul>
                          {currentReferences.map((ref, refIndex) => (
                            <li key={refIndex}>
                              <a href={ref.url} target="_blank" rel="noopener noreferrer">{ref.name}</a>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
          {loading && <div className="typing-indicator">Typing...</div>}
        </div>
        <form onSubmit={handleSubmit} className="chat-input-form">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type your message here"
          />
          <button type="submit" disabled={loading}>
            Send
          </button>
        </form>
      </div>
    </div>
  );
}

export default ChatApp;
