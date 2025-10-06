"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

interface User {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  is_admin: boolean;
}

interface Resource {
  id: number;
  name: string;
  hostname: string;
  type: string;
}

interface RecordedSession {
  id: number;
  session_id: string;
  user_id: number;
  resource_id: number;
  started_at: string;
  ended_at: string | null;
  duration: number | null;
  status: string;
  suspicious_detected: boolean;
  user: User;
  resource: Resource;
}

interface SessionEvent {
  id: number;
  event_type: string;
  data: string;
  timestamp: string;
  sequence: number;
}

interface SuspiciousCommand {
  id: number;
  command: string;
  timestamp: string;
  severity: string;
  attempt_count: number;
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<RecordedSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [user, setUser] = useState<User | null>(null);
  const [selectedSession, setSelectedSession] = useState<RecordedSession | null>(null);
  const [sessionEvents, setSessionEvents] = useState<SessionEvent[]>([]);
  const [suspiciousCommands, setSuspiciousCommands] = useState<SuspiciousCommand[]>([]);
  const [showPlaybackModal, setShowPlaybackModal] = useState(false);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentEventIndex, setCurrentEventIndex] = useState(0);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);

  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }
    fetchUserData();
  }, [router]);

  useEffect(() => {
    if (user) {
      fetchSessions();
    }
  }, [user]);

  const fetchUserData = async () => {
    try {
      const response = await fetch('/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          action: 'getUser',
          token: localStorage.getItem('token')
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch user data');
      }

      setUser(data);
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    }
  };

  const fetchSessions = async () => {
    try {
      const token = localStorage.getItem('token');
      const endpoint = user?.is_admin ? '/api/sessions' : '/api/sessions/my-sessions';
      
      const response = await fetch(`http://localhost:8000${endpoint}?limit=100`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setSessions(data);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to fetch sessions');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load sessions');
    } finally {
      setLoading(false);
    }
  };

  const fetchSessionPlayback = async (sessionId: string) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:8000/api/sessions/${sessionId}/playback`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setSessionEvents(data.events || []);
        setSuspiciousCommands(data.suspicious_commands || []);
        setShowPlaybackModal(true);
        setCurrentEventIndex(0);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to fetch session playback');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load session playback');
    }
  };

  const startPlayback = () => {
    setIsPlaying(true);
    setCurrentEventIndex(0);
    
    const playbackInterval = setInterval(() => {
      setCurrentEventIndex(prev => {
        if (prev >= sessionEvents.length - 1) {
          clearInterval(playbackInterval);
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 1000 / playbackSpeed);
  };

  const stopPlayback = () => {
    setIsPlaying(false);
  };

  const formatDuration = (seconds: number | null) => {
    if (!seconds) return 'N/A';
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  const getStatusBadge = (status: string) => {
    const baseClasses = "px-2 py-1 rounded-full text-xs font-medium";
    switch (status) {
      case 'recording':
        return `${baseClasses} bg-yellow-100 text-yellow-800`;
      case 'completed':
        return `${baseClasses} bg-green-100 text-green-800`;
      case 'terminated_security':
        return `${baseClasses} bg-red-100 text-red-800`;
      case 'failed':
        return `${baseClasses} bg-red-100 text-red-800`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800`;
    }
  };

  const getEventColor = (eventType: string) => {
    switch (eventType) {
      case 'command_executed':
        return 'text-yellow-300';
      case 'command_input':
        return 'text-blue-300';
      case 'output':
        return 'text-green-400';
      case 'warning':
        return 'text-orange-300';
      case 'security_violation':
        return 'text-red-400';
      case 'warning_triggered':
        return 'text-orange-400';
      default:
        return 'text-gray-400';
    }
  };

  const getEventIcon = (eventType: string) => {
    switch (eventType) {
      case 'command_executed':
        return '🚀';
      case 'command_input':
        return '⌨️';
      case 'output':
        return '📤';
      case 'warning':
        return '⚠️';
      case 'security_violation':
        return '🔴';
      case 'warning_triggered':
        return '🚫';
      default:
        return '📝';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading sessions...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <button
                onClick={() => router.push('/dashboard')}
                className="bg-gray-100 hover:bg-gray-200 px-3 py-1 rounded text-sm mr-4"
              >
                ← Back to Dashboard
              </button>
              <h1 className="text-xl font-semibold text-gray-800">
                {user?.is_admin ? 'All Session Recordings' : 'My Session Recordings'}
              </h1>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 p-4 bg-red-50 text-red-700 rounded-md">
            {error}
          </div>
        )}

        <div className="bg-white rounded-lg shadow-md overflow-hidden">
          {sessions.length > 0 ? (
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Resource
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Started
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Duration
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Suspicious
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {sessions.map((session) => (
                  <tr key={session.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900">
                        {session.user.username}
                      </div>
                      <div className="text-sm text-gray-500">
                        {session.user.email}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900">
                        {session.resource.name}
                      </div>
                      <div className="text-sm text-gray-500">
                        {session.resource.hostname}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(session.started_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {formatDuration(session.duration)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={getStatusBadge(session.status)}>
                        {session.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {session.suspicious_detected ? (
                        <span className="px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs font-medium">
                          {suspiciousCommands.filter(cmd => 
                            sessions.find(s => s.id === session.id)
                          ).length} detected
                        </span>
                      ) : (
                        <span className="px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs font-medium">
                          Clean
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <button
                        onClick={() => {
                          setSelectedSession(session);
                          fetchSessionPlayback(session.session_id);
                        }}
                        className="text-blue-600 hover:text-blue-900 mr-3"
                      >
                        Playback
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="text-center py-12">
              <div className="text-gray-400 mb-4">
                <svg className="mx-auto h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z" />
                </svg>
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">No sessions found</h3>
              <p className="text-gray-500">No session recordings available yet.</p>
            </div>
          )}
        </div>
      </main>

      {/* Enhanced Playback Modal */}
      {showPlaybackModal && selectedSession && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex items-center justify-center p-4 z-50">
          <div className="relative bg-white rounded-lg shadow-xl max-w-6xl w-full mx-auto">
            <div className="p-6">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-semibold">
                  Session Playback - {selectedSession.resource.name}
                </h3>
                <button
                  onClick={() => setShowPlaybackModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ×
                </button>
              </div>
              
              <div className="mb-4 grid grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="font-medium">User:</span> {selectedSession.user.username}
                </div>
                <div>
                  <span className="font-medium">Resource:</span> {selectedSession.resource.name}
                </div>
                <div>
                  <span className="font-medium">Started:</span> {new Date(selectedSession.started_at).toLocaleString()}
                </div>
                <div>
                  <span className="font-medium">Duration:</span> {formatDuration(selectedSession.duration)}
                </div>
              </div>

              {/* Security Summary */}
              {suspiciousCommands.length > 0 && (
                <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
                  <h4 className="font-semibold text-red-800 mb-2">Security Events Detected</h4>
                  <div className="space-y-2">
                    {suspiciousCommands.map((cmd, index) => (
                      <div key={cmd.id} className="flex justify-between items-center text-sm">
                        <code className="bg-red-100 px-2 py-1 rounded">{cmd.command}</code>
                        <span className="text-red-700">Attempt {cmd.attempt_count}</span>
                        <span className="text-red-600">{new Date(cmd.timestamp).toLocaleTimeString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="bg-gray-900 text-green-400 font-mono text-sm p-4 rounded h-96 overflow-y-auto mb-4">
                {sessionEvents.slice(0, currentEventIndex + 1).map((event, index) => (
                  <div key={event.id} className="mb-1 flex items-start">
                    <span className="mr-2 text-xs opacity-70 mt-1">
                      {getEventIcon(event.event_type)}
                    </span>
                    <span className={`mr-2 text-xs opacity-70 mt-1 ${getEventColor(event.event_type)}`}>
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                    <div className={`flex-1 ${getEventColor(event.event_type)}`}>
                      {event.event_type === 'command_executed' && (
                        <div>
                          <span className="text-gray-500">$ </span>
                          <span className="text-yellow-300">{event.data}</span>
                        </div>
                      )}
                      {event.event_type === 'command_input' && (
                        <div className="text-blue-300 opacity-70">
                          [Input: {event.data}]
                        </div>
                      )}
                      {event.event_type === 'output' && (
                        <div className="whitespace-pre-wrap">{event.data}</div>
                      )}
                      {event.event_type === 'warning_triggered' && (
                        <div className="text-orange-300">
                          ⚠️ {JSON.parse(event.data).warning}
                        </div>
                      )}
                      {event.event_type === 'security_violation' && (
                        <div className="text-red-400 font-semibold">
                          🔴 SECURITY VIOLATION: {JSON.parse(event.data).reason}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              <div className="flex justify-between items-center">
                <div className="flex space-x-2">
                  <button
                    onClick={startPlayback}
                    disabled={isPlaying}
                    className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded disabled:opacity-50"
                  >
                    Start Playback
                  </button>
                  <button
                    onClick={stopPlayback}
                    disabled={!isPlaying}
                    className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded disabled:opacity-50"
                  >
                    Stop
                  </button>
                  <select
                    value={playbackSpeed}
                    onChange={(e) => setPlaybackSpeed(Number(e.target.value))}
                    className="border border-gray-300 rounded px-2 py-2"
                  >
                    <option value={0.5}>0.5x</option>
                    <option value={1}>1x</option>
                    <option value={2}>2x</option>
                    <option value={5}>5x</option>
                  </select>
                </div>
                <div className="text-sm text-gray-600">
                  Event {currentEventIndex + 1} of {sessionEvents.length}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}