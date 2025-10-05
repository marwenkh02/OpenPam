"use client";
import { useEffect, useRef, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';

interface Resource {
  id: number;
  name: string;
  hostname: string;
  port?: number;
  type: string;
}

interface Credential {
  id: number;
  name: string;
  type: string;
  username: string;
  is_active: boolean;
  last_rotated_at: string | null;
  rotation_interval_days: number | null;
}

export default function TerminalPage() {
  const params = useParams();
  const router = useRouter();
  const terminalRef = useRef<HTMLDivElement>(null);
  const [terminal, setTerminal] = useState<Terminal | null>(null);
  const [fitAddon, setFitAddon] = useState<FitAddon | null>(null);
  const [websocket, setWebsocket] = useState<WebSocket | null>(null);
  const [resource, setResource] = useState<Resource | null>(null);
  const [status, setStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('connecting');
  const [error, setError] = useState('');
  const [isConnecting, setIsConnecting] = useState(false);
  
  // Credential management state
  const [availableCredentials, setAvailableCredentials] = useState<Credential[]>([]);
  const [selectedCredentialId, setSelectedCredentialId] = useState<string>('');
  const [isLoadingCredentials, setIsLoadingCredentials] = useState(false);

  const resourceId = params.resourceId as string;

  useEffect(() => {
    if (resourceId) {
      initializeTerminal();
      fetchResourceDetails();
    }
    
    return () => {
      if (websocket) {
        websocket.close(1000, 'Component unmounted');
      }
      if (terminal) {
        terminal.dispose();
      }
    };
  }, [resourceId]);

  const initializeTerminal = () => {
    // Clean up existing terminal
    if (terminal) {
      terminal.dispose();
    }

    const term = new Terminal({
      cursorBlink: true,
      theme: {
        background: '#1a202c',
        foreground: '#e2e8f0',
        cursor: '#e2e8f0'
      },
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      cols: 80,
      rows: 24
    });

    const fit = new FitAddon();
    term.loadAddon(fit);

    if (terminalRef.current) {
      // Clear any existing content
      terminalRef.current.innerHTML = '';
      
      term.open(terminalRef.current);
      fit.fit();
      
      term.write('\x1b[33mInitializing OpenPAM SSH Terminal...\x1b[0m\r\n');
      term.write('\x1b[36mEstablishing secure connection...\x1b[0m\r\n\r\n');

      setTerminal(term);
      setFitAddon(fit);
    }
  };

  const fetchResourceDetails = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No authentication token found');
      }

      console.log('Fetching resource details for ID:', resourceId);
      
      const response = await fetch(`/api/resources/${resourceId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const resourceData = await response.json();
        console.log('Resource details:', resourceData);
        setResource(resourceData);
        
        // Fetch credentials after resource details are loaded
        await fetchCredentials();
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to fetch resource details');
      }
    } catch (err: any) {
      console.error('Error fetching resource:', err);
      setError(err.message || 'Failed to load resource details');
      setStatus('error');
    }
  };

  const fetchCredentials = async () => {
    try {
      setIsLoadingCredentials(true);
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No authentication token found');
      }

      console.log('Fetching credentials for resource:', resourceId);
      
      const response = await fetch(`/api/resources/${resourceId}/credentials`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const credentialsData = await response.json();
        console.log('Available credentials:', credentialsData);
        setAvailableCredentials(credentialsData);
        
        if (credentialsData.length > 0) {
          // Auto-select the first credential
          setSelectedCredentialId(credentialsData[0].id.toString());
          console.log('Auto-selected credential:', credentialsData[0].id);
        } else {
          console.warn('No credentials available for this resource');
          setError('No credentials configured for this resource. Please contact an administrator.');
          setStatus('error');
        }
      } else if (response.status === 403) {
        // User doesn't have permission to view credentials, but can still try to connect
        console.log('User does not have permission to view credentials, proceeding with default connection');
        setAvailableCredentials([]);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to fetch credentials');
      }
    } catch (err: any) {
      console.error('Error fetching credentials:', err);
      // Don't set error state here - we can still try to connect without credential selection
      setAvailableCredentials([]);
    } finally {
      setIsLoadingCredentials(false);
    }
  };

  
  // Auto-connect when terminal is ready and credentials (if any) have loaded
  useEffect(() => {
    // Only attempt to connect when:
    // - terminal is initialized
    // - we are in 'connecting' state and no websocket exists
    // - credentials have finished loading (so selectedCredentialId is set if available)
    if (terminal && !isLoadingCredentials && !websocket && status === 'connecting') {
      connectWebSocket();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [terminal, isLoadingCredentials, selectedCredentialId]);

  const connectWebSocket = () => {
    if (isConnecting || websocket) return;
    
    setIsConnecting(true);
    setStatus('connecting');
    setError('');

    const token = localStorage.getItem('token');
    if (!token) {
      setError('Authentication required');
      setStatus('error');
      setIsConnecting(false);
      router.push('/login');
      return;
    }

    // Use the backend URL directly for WebSocket
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
    let wsUrl = `${backendUrl.replace('http', 'ws')}/ws/resources/${resourceId}/ssh?token=${token}`;
    
    // Add credential ID if selected
    if (selectedCredentialId) {
      wsUrl += `&credential_id=${selectedCredentialId}`;
      console.log('Connecting with credential ID:', selectedCredentialId);
    } else {
      console.log('Connecting without specific credential (using default)');
    }
    
    console.log('Connecting to WebSocket:', wsUrl);
    
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('WebSocket connection opened');
      setStatus('connected');
      setError('');
      setIsConnecting(false);
      
      if (terminal) {
        terminal.write('\r\n\x1b[32m✓ Connected to OpenPAM gateway\x1b[0m\r\n');
        terminal.write('\x1b[33mNegotiating SSH connection...\x1b[0m\r\n');
        
        // Display credential info if available
        const selectedCredential = availableCredentials.find(
          cred => cred.id.toString() === selectedCredentialId
        );
        if (selectedCredential) {
          terminal.write(`\x1b[36mUsing credential: ${selectedCredential.name} (${selectedCredential.username})\x1b[0m\r\n`);
        }
      }
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        console.log('WebSocket message received:', message);
        
        switch (message.type) {
          case 'output':
            if (terminal) {
              terminal.write(message.data);
            }
            break;
          case 'connected':
            console.log('SSH connection established');
            if (terminal) {
              terminal.write('\r\n\x1b[32m✓ SSH session established\x1b[0m\r\n');
              terminal.write('\x1b[36mYou are now connected to the remote server\x1b[0m\r\n\r\n');
            }
            break;
          case 'error':
            console.error('SSH connection error:', message.message);
            setError(message.message);
            setStatus('error');
            if (terminal) {
              terminal.write(`\r\n\x1b[31m✗ Connection Error: ${message.message}\x1b[0m\r\n`);
              terminal.write('\x1b[33mCheck if:\x1b[0m\r\n');
              terminal.write('1. The target server is running and accessible\r\n');
              terminal.write('2. SSH credentials are properly configured\r\n');
              terminal.write('3. Your access request is still valid\r\n');
              terminal.write('4. The selected credential has correct permissions\r\n');
            }
            break;
          default:
            console.log('Unknown message type:', message.type);
        }
      } catch (err) {
        console.error('Error parsing WebSocket message:', err);
        // Try to display raw data if JSON parsing fails
        if (terminal) {
          terminal.write(event.data);
        }
      }
    };

    ws.onclose = (event) => {
      console.log('WebSocket connection closed:', event.code, event.reason);
      setStatus('disconnected');
      setIsConnecting(false);
      
      if (event.code !== 1000) {
        const errorMsg = event.reason || `Connection closed with code ${event.code}`;
        setError(errorMsg);
        if (terminal) {
          terminal.write(`\r\n\x1b[31m✗ Connection closed: ${errorMsg}\x1b[0m\r\n`);
        }
      } else {
        if (terminal) {
          terminal.write('\r\n\x1b[33mSession ended by user\x1b[0m\r\n');
        }
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setStatus('error');
      setIsConnecting(false);
      setError('WebSocket connection failed. Make sure the backend server is running on port 8000.');
      
      if (terminal) {
        terminal.write('\r\n\x1b[31m✗ WebSocket connection failed\x1b[0m\r\n');
        terminal.write('\x1b[33mEnsure backend server is running:\x1b[0m\r\n');
        terminal.write('1. Check if backend is running on port 8000\r\n');
        terminal.write('2. Verify CORS settings\r\n');
        terminal.write('3. Check network connectivity\r\n');
      }
    };

    setWebsocket(ws);

    // Setup terminal input handling
    if (terminal) {
      terminal.onData((data) => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            type: 'input',
            data: data
          }));
        }
      });

      terminal.onResize((size) => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            type: 'resize',
            cols: size.cols,
            rows: size.rows
          }));
        }
      });

      // Focus the terminal
      terminal.focus();
    }
  };

  const handleCredentialChange = (credentialId: string) => {
    setSelectedCredentialId(credentialId);
    console.log('Credential changed to:', credentialId);
    
    // If we're already connected, show a message that credential change requires reconnection
    if (status === 'connected' && terminal) {
      terminal.write('\r\n\x1b[33mCredential change detected. Reconnect to use new credential.\x1b[0m\r\n');
    }
  };

  const handleReconnect = () => {
    if (websocket) {
      websocket.close(1000, 'Reconnecting');
      setWebsocket(null);
    }
    setError('');
    setStatus('connecting');
    initializeTerminal();
    setTimeout(() => connectWebSocket(), 500);
  };

  const handleDisconnect = () => {
    if (websocket) {
      websocket.close(1000, 'User disconnected');
      setWebsocket(null);
    }
    if (terminal) {
      terminal.write('\r\n\x1b[33mDisconnecting...\x1b[0m\r\n');
    }
    setTimeout(() => router.push('/dashboard'), 1000);
  };

  const getStatusColor = () => {
    switch (status) {
      case 'connecting': return 'bg-yellow-500';
      case 'connected': return 'bg-green-500';
      case 'disconnected': return 'bg-gray-500';
      case 'error': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusText = () => {
    switch (status) {
      case 'connecting': return 'Connecting...';
      case 'connected': return 'Connected';
      case 'disconnected': return 'Disconnected';
      case 'error': return 'Error';
      default: return 'Unknown';
    }
  };

  const getSelectedCredential = () => {
    return availableCredentials.find(cred => cred.id.toString() === selectedCredentialId);
  };

  useEffect(() => {
    const connectToSSH = async () => {
      if (!resource || !selectedCredentialId || !localStorage.getItem('token')) return;

      try {
        const selectedCredential = availableCredentials.find(
          (cred) => cred.id.toString() === selectedCredentialId
        );

        console.log('🔧 Terminal connection details:', {
          resource: resource.name,
          hostname: resource.hostname,
          port: resource.port || 22,
          credential: selectedCredential?.name || 'Default',
          credentialType: selectedCredential?.type || 'N/A',
        });

        // Your existing WebSocket connection logic
        connectWebSocket();
      } catch (error: any) {
        console.error('💥 SSH connection failed:', error);
        setStatus('error');
        setError(`Connection failed: ${error.message || 'Unknown error'}`);
      }
    };

    connectToSSH();
  }, [resource, selectedCredentialId, availableCredentials]);

  return (
    <div className="h-screen flex flex-col bg-gray-900">
      {/* Header */}
      <div className="bg-gray-800 text-white p-4 flex justify-between items-center">
        <div className="flex items-center space-x-4">
          <button
            onClick={() => router.push('/dashboard')}
            className="bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-sm"
          >
            ← Back to Dashboard
          </button>
          <div>
            <h1 className="text-lg font-semibold">
              {resource?.name || `Resource ${resourceId}`}
            </h1>
            <p className="text-sm text-gray-300">
              {resource?.hostname}:{resource?.port || 22} • SSH Terminal
            </p>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          {/* Credential Selection */}
          {availableCredentials.length > 0 && (
            <div className="flex items-center space-x-2">
              <label htmlFor="credential-select" className="text-sm text-gray-300">
                Credential:
              </label>
              <select
                id="credential-select"
                value={selectedCredentialId}
                onChange={(e) => handleCredentialChange(e.target.value)}
                disabled={status === 'connected' || isConnecting}
                className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-white disabled:opacity-50"
              >
                {availableCredentials.map((credential) => (
                  <option key={credential.id} value={credential.id}>
                    {credential.name} ({credential.username})
                  </option>
                ))}
              </select>
            </div>
          )}

          {isLoadingCredentials && (
            <div className="text-sm text-gray-300">
              Loading credentials...
            </div>
          )}

          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${getStatusColor()}`}></div>
            <span className="text-sm">{getStatusText()}</span>
          </div>
          
          {status === 'error' || status === 'disconnected' ? (
            <button
              onClick={handleReconnect}
              disabled={isConnecting}
              className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded text-sm disabled:opacity-50"
            >
              {isConnecting ? 'Reconnecting...' : 'Reconnect'}
            </button>
          ) : null}
          
          <button
            onClick={handleDisconnect}
            className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded text-sm"
          >
            Disconnect
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-900 text-red-100 p-3">
          <div className="flex justify-between items-center">
            <div className="flex-1">
              <span className="font-semibold">Connection Error: </span>
              <span>{error}</span>
            </div>
            <button
              onClick={() => setError('')}
              className="text-red-300 hover:text-white ml-4"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* Connection Help */}
      {status === 'connecting' && (
        <div className="bg-blue-900 text-blue-100 p-3">
          <div className="flex items-center space-x-2">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
            <span>
              Establishing secure SSH connection via OpenPAM gateway...
              {selectedCredentialId && (
                <span className="ml-2">
                  Using credential: {getSelectedCredential()?.name}
                </span>
              )}
            </span>
          </div>
        </div>
      )}

      {/* Credential Info Banner */}
      {selectedCredentialId && status === 'connected' && (
        <div className="bg-green-900 text-green-100 p-2 text-sm">
          <div className="flex items-center justify-center space-x-2">
            <span>Connected using credential:</span>
            <span className="font-semibold">
              {getSelectedCredential()?.name} ({getSelectedCredential()?.username})
            </span>
            <span className="text-green-300">•</span>
            <span className="text-green-300">
              Type: {getSelectedCredential()?.type}
            </span>
          </div>
        </div>
      )}

      {/* No Credentials Warning */}
      {availableCredentials.length === 0 && !isLoadingCredentials && (
        <div className="bg-yellow-900 text-yellow-100 p-2 text-sm">
          <div className="flex items-center justify-center space-x-2">
            <span>⚠️ No credentials available or insufficient permissions to view credentials.</span>
            <span>Using default system credential.</span>
          </div>
        </div>
      )}

      {/* Terminal Container */}
      <div 
        ref={terminalRef} 
        className="flex-1 p-2"
      />
      
      {/* Help Footer */}
      <div className="bg-gray-800 text-gray-300 p-2 text-xs">
        <div className="flex justify-between items-center">
          <span>OpenPAM Web SSH Terminal - All sessions are logged and monitored</span>
          <div className="flex space-x-4">
            <span>Secure Gateway Connection</span>
            {selectedCredentialId && (
              <span>Credential: {getSelectedCredential()?.name}</span>
            )}
            {isConnecting && (
              <span className="text-yellow-400">Establishing connection...</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}