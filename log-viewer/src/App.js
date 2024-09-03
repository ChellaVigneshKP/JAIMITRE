// App.js
import React from 'react';
import './App.css';
import ChatApp from './ChatApp/ChatApp';
import LogViewer from './Log/LogViewer';
import SearchTool from './Search/SearchTool';
import { ButtonProvider } from './ButtonContext';

function App() {
  return (
    <ButtonProvider>
      <div className="App">
        <div className="main-container">
          <div className="side-section-left">
            <LogViewer />
          </div>
          <div className="chat-section">
            <ChatApp />
          </div>
          <div className="side-section-right">
            <SearchTool />
          </div>
        </div>
      </div>
    </ButtonProvider>
  );
}

export default App;
