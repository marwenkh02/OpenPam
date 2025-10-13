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
  const [securityWarning, setSecurityWarning] = useState<string | null>(null);
  const [realtimeWarning, setRealtimeWarning] = useState<string | null>(null);
  const [blockedCommand, setBlockedCommand] = useState<string | null>(null);
  
  const [availableCredentials, setAvailableCredentials] = useState<Credential[]>([]);
  const [selectedCredentialId, setSelectedCredentialId] = useState<string>('');
  const [isLoadingCredentials, setIsLoadingCredentials] = useState(false);

  const resourceId = params.resourceId as string;

  useEffect(() => {
    initializeTerminal();
    
    return () => {
      if (websocket) {
        websocket.close(1000, 'Component unmounted');
      }
      if (terminal) {
        terminal.dispose();
      }
    };
  }, []);

  useEffect(() => {
    if (resourceId) {
      fetchResourceDetails();
    }
  }, [resourceId]);

  useEffect(() => {
    if (terminal && !isLoadingCredentials && resource && status === 'connecting') {
      connectWebSocket();
    }
  }, [terminal, isLoadingCredentials, resource, selectedCredentialId]);

  const initializeTerminal = () => {
    if (terminal) {
      terminal.dispose();
    }

    const term = new Terminal({
      cursorBlink: true,
      theme: {
        background: '#1a202c',
        foreground: '#e2e8f0',
        cursor: '#e2e8f0',
        cursorAccent: '#1a202c'
      },
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      cols: 80,
      rows: 24,
      allowProposedApi: true,
      // Valid xterm.js options
      disableStdin: false,
      scrollback: 1000,
      tabStopWidth: 8,
      convertEol: true
    });

    const fit = new FitAddon();
    term.loadAddon(fit);

    if (terminalRef.current) {
      terminalRef.current.innerHTML = '';
      
      term.open(terminalRef.current);
      fit.fit();
      
      // Write initial message
      term.writeln('\x1b[33mInitializing OpenPAM SSH Terminal...\x1b[0m');
      term.writeln('\x1b[36mEstablishing secure connection...\x1b[0m');
      term.writeln('\x1b[35m⚠️  Security: Command monitoring enabled\x1b[0m\r\n');

      setTerminal(term);
      setFitAddon(fit);
    }
  };

  const connectWebSocket = () => {
    if (isConnecting || websocket) return;
    
    setIsConnecting(true);
    setStatus('connecting');
    setError('');
    setSecurityWarning(null);
    setRealtimeWarning(null);
    setBlockedCommand(null);

    const token = localStorage.getItem('token');
    if (!token) {
      setError('Authentication required');
      setStatus('error');
      setIsConnecting(false);
      router.push('/login');
      return;
    }

    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
    let wsUrl = `${backendUrl.replace('http', 'ws')}/ws/resources/${resourceId}/ssh?token=${token}`;
    
    if (selectedCredentialId) {
      wsUrl += `&credential_id=${selectedCredentialId}`;
    }
    
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setStatus('connected');
      setError('');
      setIsConnecting(false);
      
      if (terminal) {
        terminal.writeln('\r\n\x1b[32m✓ Connected to OpenPAM gateway\x1b[0m');
        terminal.writeln('\x1b[33mNegotiating SSH connection...\x1b[0m');
        
        const selectedCredential = availableCredentials.find(
          cred => cred.id.toString() === selectedCredentialId
        );
        if (selectedCredential) {
          terminal.writeln(`\x1b[36mUsing credential: ${selectedCredential.name} (${selectedCredential.username})\x1b[0m`);
        }
        
        terminal.writeln('\x1b[35m🔒 Security monitoring active\x1b[0m\r\n');
        
        // Set up terminal input handling
        terminal.onData((data) => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              type: 'input',
              data: data
            }));
          }
        });

        // Handle terminal resize
        terminal.onResize((size) => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              type: 'resize',
              cols: size.cols,
              rows: size.rows
            }));
          }
        });

        terminal.focus();
      }
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        
        switch (message.type) {
          case 'output':
            if (terminal) {
              terminal.write(message.data);
            }
            break;
          case 'connected':
            if (terminal) {
              terminal.writeln('\r\n\x1b[32m✓ SSH session established\x1b[0m');
              terminal.writeln('\x1b[36mYou are now connected to the remote server\x1b[0m\r\n');
              terminal.focus();
            }
            break;
          case 'status':
            if (terminal) {
              terminal.writeln(`\x1b[33m${message.message}\x1b[0m`);
            }
            break;
          case 'security_warning':
            setSecurityWarning(message.message);
            if (message.blocked_command) {
              setBlockedCommand(message.blocked_command);
              // The blocked command message is already sent as output from backend
            } else {
              // Warning but not blocked
              if (terminal) {
                terminal.write(`\r\n\x1b[33m⚠️  ${message.message}\x1b[0m\r\n`);
              }
            }
            break;
          case 'realtime_warning':
            setRealtimeWarning(message.message);
            // Show real-time warning
            if (terminal) {
              terminal.write(`\r\n\x1b[33m⚠️  ${message.message}\x1b[0m\r\n`);
            }
            break;
          case 'error':
            setError(message.message);
            setStatus('error');
            if (terminal) {
              terminal.writeln(`\r\n\x1b[31m✗ Connection Error: ${message.message}\x1b[0m`);
            }
            break;
          default:
            console.log('Unknown message type:', message.type);
        }
      } catch (err) {
        console.error('Error parsing WebSocket message:', err);
        // If it's not JSON, treat it as raw terminal output
        if (terminal) {
          terminal.write(event.data);
        }
      }
    };

    ws.onclose = (event) => {
      setStatus('disconnected');
      setIsConnecting(false);
      
      if (event.code !== 1000) {
        const errorMsg = event.reason || `Connection closed with code ${event.code}`;
        setError(errorMsg);
        if (terminal) {
          terminal.writeln(`\r\n\x1b[31m✗ Connection closed: ${errorMsg}\x1b[0m`);
        }
      } else {
        if (terminal) {
          terminal.writeln('\r\n\x1b[33mSession ended by user\x1b[0m');
        }
      }
    };

    ws.onerror = (error) => {
      setStatus('error');
      setIsConnecting(false);
      setError('WebSocket connection failed.');
      
      if (terminal) {
        terminal.writeln('\r\n\x1b[31m✗ WebSocket connection failed\x1b[0m');
      }
    };

    setWebsocket(ws);
  };

  const fetchResourceDetails = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No authentication token found');
      }

      const response = await fetch(`/api/resources/${resourceId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const resourceData = await response.json();
        setResource(resourceData);
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

      const response = await fetch(`/api/resources/${resourceId}/credentials`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const credentialsData = await response.json();
        setAvailableCredentials(credentialsData);
        
        if (credentialsData.length > 0) {
          setSelectedCredentialId(credentialsData[0].id.toString());
        }
      } else if (response.status === 403) {
        setAvailableCredentials([]);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to fetch credentials');
      }
    } catch (err: any) {
      console.error('Error fetching credentials:', err);
      setAvailableCredentials([]);
    } finally {
      setIsLoadingCredentials(false);
    }
  };

  const clearWarnings = () => {
    setSecurityWarning(null);
    setRealtimeWarning(null);
    setBlockedCommand(null);
  };

  const handleReconnect = () => {
    if (websocket) {
      websocket.close(1000, 'Reconnecting');
      setWebsocket(null);
    }
    setError('');
    setStatus('connecting');
    
    setTimeout(() => {
      connectWebSocket();
    }, 500);
  };

  const handleDisconnect = () => {
    if (websocket) {
      websocket.close(1000, 'User disconnected');
      setWebsocket(null);
    }
    if (terminal) {
      terminal.writeln('\r\n\x1b[33mDisconnecting...\x1b[0m');
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

  // Handle window resize
  useEffect(() => {
    const handleResize = () => {
      if (fitAddon) {
        fitAddon.fit();
      }
    };

    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, [fitAddon]);

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
                onChange={(e) => setSelectedCredentialId(e.target.value)}
                disabled={status === 'connected' || isConnecting}
                className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-white disabled:opacity-50"
              >
                {availableCredentials.map((credential) => (
                  <option key={credential.id} value={credential.id.toString()}>
                    {credential.name} ({credential.username})
                  </option>
                ))}
              </select>
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

      {/* Security Warnings */}
      {securityWarning && (
        <div className={`p-3 ${blockedCommand ? 'bg-red-900' : 'bg-yellow-900'} text-white`}>
          <div className="flex justify-between items-center">
            <div className="flex-1">
              <span className="font-semibold">Security Alert: </span>
              <span>{securityWarning}</span>
              {blockedCommand && (
                <div className="text-sm mt-1">
                  Blocked command: <code className="bg-red-800 px-1 rounded">{blockedCommand}</code>
                </div>
              )}
            </div>
            <button
              onClick={clearWarnings}
              className="text-white hover:text-gray-300 ml-4"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* Real-time Warning */}
      {realtimeWarning && !securityWarning && (
        <div className="bg-yellow-900 text-yellow-100 p-3">
          <div className="flex justify-between items-center">
            <div className="flex-1">
              <span className="font-semibold">Warning: </span>
              <span>{realtimeWarning}</span>
            </div>
            <button
              onClick={clearWarnings}
              className="text-yellow-300 hover:text-yellow-100 ml-4"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* Connection Status */}
      {status === 'connecting' && (
        <div className="bg-blue-900 text-blue-100 p-3">
          <div className="flex items-center space-x-2">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
            <span>Establishing secure SSH connection...</span>
          </div>
        </div>
      )}

      {/* Terminal Container */}
      <div 
        ref={terminalRef} 
        className="flex-1 p-2"
        onClick={() => terminal?.focus()}
      />
      
      {/* Security Footer */}
      <div className="bg-gray-800 text-gray-300 p-2 text-xs">
        <div className="flex justify-between items-center">
          <span>🔒 OpenPAM Web SSH Terminal - Security monitoring active</span>
          <div className="flex space-x-4">
            <span>All sessions are recorded</span>
            <span>Suspicious commands are blocked</span>
          </div>
        </div>
      </div>
    </div>
  );
}