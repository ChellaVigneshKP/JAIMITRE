import React, { useState, useEffect, useContext } from 'react';
import axios from 'axios';
import DataFrame from './DataFrame';
import LogData from './LogData';
import { ButtonContext } from '../ButtonContext'; // Import context
import { Pie } from 'react-chartjs-2';
import ChartDataLabels from 'chartjs-plugin-datalabels';
import './LogViewer.css';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  Title
} from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend, Title, ChartDataLabels);

const LogViewer = () => {
  const [dataFrame, setDataFrame] = useState(null);
  const [logData, setLogData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [mitreData, setMitreData] = useState({});
  const { setButtonMessage } = useContext(ButtonContext);
  const fetchLogData = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('http://127.0.0.1:5000/generate-log');
      if (response.data && typeof response.data === 'object') {
        const { attack_technique, incident_grade, data_frame, log_data } = response.data;
        if (
          data_frame && typeof data_frame === 'object' && !Array.isArray(data_frame) &&
          log_data && typeof log_data === 'string'
        ) {
          setDataFrame(data_frame);
          setLogData(log_data);
          let message = null;
          if (incident_grade !== 'FalsePositive') {
            const techniqueString = Array.isArray(attack_technique)
              ? attack_technique.join(', ')
              : attack_technique;

            message = `Predicted Incident Grade is: ${incident_grade}\nPredicted MITRE ATT&CK is: ${techniqueString}`;
          }
          else {
            message = `Predicted Incident Grade is: ${incident_grade}\nNo Prediction for MITRE ATT&CK`;
          }
          fetchMitreData();
          return message;
        } else {
          throw new Error('Response structure is incorrect');
        }
      } else {
        throw new Error('Response is not an object');
      }
    } catch (error) {
      console.error('Error fetching log data:', error);
      setError(`Failed to fetch data: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const fetchMitreData = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:5000/predict-attack-technique');
      setMitreData(response.data);
      const techniques = Object.keys(response.data).join(', ');
      return `MITRE ATT&CK Data: ${Object.keys(response.data).length} techniques found:\n${techniques}`;
    } catch (error) {
      console.error('Error fetching MITRE ATT&CK data:', error);
      setError(`Failed to fetch MITRE ATT&CK data: ${error.message}`);
      return `Failed to fetch MITRE ATT&CK data: ${error.message}`;
    }
  };

  const processFileFromUploads = async (fileName) => {
    try {
      const response = await axios.post('http://localhost:4000/process-file-from-uploads', { fileName });
      const { fileNamed, fileHash, mitreAttck } = response.data;
      const mitreAttckString = mitreAttck ? mitreAttck.join(', ') : 'N/A';
      const message = `File Name: ${fileNamed}\nFile Hash: ${fileHash}\nMITRE ATT&CK: ${mitreAttckString}`;
      return message;
    } catch (error) {
      console.error('Error processing file from uploads:', error.message);
    }
  };
  
  const checkUrl = async (url) => {
    if (!url) return 'No URL provided';
  
    try {
      const response = await axios.post('http://localhost:4000/domaincheck', { url });
      const { domain, isSafe } = response.data;
      const safetyMessage = isSafe ? `${domain} is safe` : `${domain} is not safe`;
      return safetyMessage;
    } catch (error) {
      return `Error checking URL: ${error.message}`;
    }
  };

  useEffect(() => {
    fetchMitreData();
  }, []);

  const handleButtonClick = async () => {
    setLoading(true);
    setError(null);
    try {
      const [logMessage] = await Promise.all([
        fetchLogData(),
      ]);
      setButtonMessage({ role: 'system', content: `${logMessage}` });
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleAutomateClick = async () => {
    setLoading(true);
    setError(null);
    try {
      const [logMessage, mitreMessage, fileMessage, urlMessage] = await Promise.all([
        fetchLogData(),
        fetchMitreData(),
        processFileFromUploads("Assign 2.pdf"),
        checkUrl("google.com"),
      ]);
      const combinedMessages = `${logMessage}\n${mitreMessage}\n${fileMessage}\n${urlMessage}`;
      const regex = /\bT\d{4}(?:\.\d{3})?\b/g;
      const mitreIds = combinedMessages.match(regex) || [];
      const mitreIdString = mitreIds ? mitreIds.join(', ') : '';
      console.log("Extracted MITRE ATT&CK IDs:", mitreIdString);
      setButtonMessage({ role: 'system', content: combinedMessages });
      const searchResponse = await axios.post('http://127.0.0.1:5000/search-attackid', { ids: mitreIdString });
      const searchData = searchResponse.data;
      const attackDetails = searchData.map(item => (
        `ID: ${item.attack_id}, Name: ${item.name}, Description: ${item.description}, Kill Chain Phases: ${item.kill_chain_phases.map(phase => `${phase.kill_chain_name} - ${phase.phase_name}`).join(', ')}`
      )).join('\n');
      setButtonMessage({ role: 'system-assistant', content: attackDetails });
      if(mitreIds.length>0){
        try {
          const response = await axios.post('http://127.0.0.1:5000/suggest-d3fend', {
            attack_ids: mitreIds
          });
          const suggestions = response.data.suggestions;
          setButtonMessage({ role: 'system-assistant', content: suggestions });
        } catch (error) {
          console.error('Error fetching D3Fend suggestions:', error);
          setButtonMessage({ role: 'system', content: 'An error occurred while fetching D3Fend suggestions.' });
        }
      }
    } catch (error) {
      setButtonMessage({ role: 'system', content: 'An error occurred during automation.' });
    } finally {
      setLoading(false);
    }
  };

  const getChartData = () => {
    const labels = [];
    const data = [];
    let othersCount = 0;
    let sortedEntries = Object.entries(mitreData).sort(([, countA], [, countB]) => countB - countA);
    sortedEntries.forEach(([technique, count], index) => {
      if (index < 9) {
        labels.push(technique);
        data.push(count);
      } else {
        othersCount += count;
      }
    });
    if (othersCount > 0) {
      labels.push('Others');
      data.push(othersCount);
    }

    return {
      labels,
      datasets: [
        {
          data,
          backgroundColor: [
            '#FF6384',
            '#36A2EB',
            '#FFCE56',
            '#4BC0C0',
            '#9966FF',
            '#FF9F40',
            '#FF6B6B',
            '#1C75BC',
            '#51C2C2',
            '#C2C2C2',
          ],
          hoverBackgroundColor: [
            '#FF6384',
            '#36A2EB',
            '#FFCE56',
            '#4BC0C0',
            '#9966FF',
            '#FF9F40',
            '#FF6B6B',
            '#1C75BC',
            '#51C2C2',
            '#A9A9A9',
          ],
        }
      ]
    };
  };

  return (
    <div className="log-viewer">
      <div className="vertical-boxes">
        <h2>Log from Server</h2>
        <div className="box">
          {logData ? <LogData data={logData} /> : <p>No Log Data yet.</p>}
        </div>
        <button onClick={() => handleButtonClick('Fetch Log Data Button Pressed')} disabled={loading} className="fetch-log">
          {loading ? 'Loading...' : 'Fetch Log Data'}
        </button>
        <button onClick={() => handleAutomateClick('Automate Button Pressed')} disabled={loading} className="automate">
          {loading ? 'Loading...' : 'Automate'}
        </button>
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <h2>Processed DataFrame</h2>
        <div className="box">
          {dataFrame ? <DataFrame data={dataFrame} /> : <p>No Data Frame yet.</p>}
        </div>
        <h2>ATT&CK Techniques</h2>
        <div className="chart-box">
          {Object.keys(mitreData).length > 0 ? (
            <Pie
              data={getChartData()}
              options={{
                plugins: {
                  legend: {
                    display: true,
                    position: 'bottom',
                    labels: {
                      generateLabels: (chart) => {
                        const data = chart.data;
                        return data.labels.map((label, index) => {
                          const value = data.datasets[0].data[index];
                          return {
                            text: `${label}: ${value}`, // Show technique and count in the legend
                            fillStyle: data.datasets[0].backgroundColor[index],
                            strokeStyle: data.datasets[0].hoverBackgroundColor[index],
                            lineWidth: 1,
                            hidden: chart.getDatasetMeta(0).data[index].hidden,
                            index: index
                          };
                        });
                      }
                    }
                  },
                  tooltip: {
                    callbacks: {
                      label: (tooltipItem) => {
                        const label = tooltipItem.label || '';
                        const value = tooltipItem.raw || 0;
                        return `${label}: ${value}`;
                      }
                    }
                  },
                  datalabels: {
                    display: false
                  }
                },
                responsive: true,
                maintainAspectRatio: false,
                layout: {
                  padding: {
                    top: 10,
                    bottom: 10,
                  },
                },
              }}
            />
          ) : (
            <p>No ATT&CK Data available yet.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default LogViewer;
