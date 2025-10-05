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
  type: string;
  hostname: string;
  port?: number;
  description?: string;
  criticality: string;
  is_active: boolean;
  is_online: boolean;
  last_checked_at?: string;
  check_interval: number;
}

interface AccessRequest {
  id: number;
  user_id: number;
  resource_id: number;
  reason?: string;
  status: string;
  requested_at: string;
  approved_at?: string;
  expires_at: string;
  user?: User;
  resource?: Resource;
  approver?: User;
}

interface AuditLog {
  id: number;
  user_id: number | null;
  admin_user_id: number | null;
  action: string;
  action_type: string;
  details: any;
  ip_address: string | null;
  user_agent: string | null;
  timestamp: string;
  access_request_id: number | null;
  resource_id: number | null;
  severity: string;
  user: User | null;
  admin_user: User | null;
  access_request: AccessRequest | null;
  resource: Resource | null;
}

interface AuditStats {
  total_logs: number;
  action_type_stats: Record<string, number>;
  severity_stats: Record<string, number>;
  recent_activity_24h: number;
}

interface ResourceCreate {
  name: string;
  type: string;
  hostname: string;
  port?: number;
  description?: string;
  criticality: string;
}

interface ResourceCheck {
  id: number;
  resource_id: number;
  checked_at: string;
  is_online: boolean;
  response_time?: number;
  error_message?: string;
  resource?: Resource;
}

interface HealthCheckResponse {
  resource_id: number;
  is_online: boolean;
  response_time?: number;
  error_message?: string;
  checked_at: string;
}

interface Credential {
  id: number;
  name: string;
  type: string;
  username: string;
  resource_id: number;
  created_at: string;
  updated_at: string;
}

export default function Dashboard() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [activeTab, setActiveTab] = useState<'overview' | 'requests' | 'admin' | 'audit' | 'resources'>('overview');
  const [resources, setResources] = useState<Resource[]>([]);
  const [myAccessRequests, setMyAccessRequests] = useState<AccessRequest[]>([]);
  const [allAccessRequests, setAllAccessRequests] = useState<AccessRequest[]>([]);
  const [pendingAccessRequests, setPendingAccessRequests] = useState<AccessRequest[]>([]);
  const [showRequestModal, setShowRequestModal] = useState(false);
  const [newRequest, setNewRequest] = useState({
    resource_id: '',
    reason: '',
    expires_at: ''
  });
  const [submitting, setSubmitting] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Credential Management State
  const [showCredentialModal, setShowCredentialModal] = useState(false);
  const [selectedResourceForCredential, setSelectedResourceForCredential] = useState<Resource | null>(null);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [newCredential, setNewCredential] = useState({
    name: '',
    type: 'password',
    username: '',
    password: '',
    private_key: ''
  });
  
  // Resource Management State
  const [showCreateResourceModal, setShowCreateResourceModal] = useState(false);
  const [showEditResourceModal, setShowEditResourceModal] = useState(false);
  const [showDeleteResourceModal, setShowDeleteResourceModal] = useState(false);
  const [selectedResource, setSelectedResource] = useState<Resource | null>(null);
  const [newResource, setNewResource] = useState<ResourceCreate>({
    name: '',
    type: 'ssh',
    hostname: '',
    port: undefined,
    description: '',
    criticality: 'medium'
  });
  const [editResource, setEditResource] = useState<Partial<ResourceCreate>>({});
  const [deleteForce, setDeleteForce] = useState(false);
  const [deleteDependencies, setDeleteDependencies] = useState<any>(null);
  
  // Audit Logs State
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditStats, setAuditStats] = useState<AuditStats | null>(null);
  const [auditFilters, setAuditFilters] = useState({
    user_id: '',
    action_type: '',
    severity: '',
    start_date: '',
    end_date: ''
  });
  const [loadingAuditLogs, setLoadingAuditLogs] = useState(false);

  // Resources filtering and search
  const [resourcesSearch, setResourcesSearch] = useState('');
  const [resourcesTypeFilter, setResourcesTypeFilter] = useState('');
  const [resourcesCriticalityFilter, setResourcesCriticalityFilter] = useState('');

  // Health Monitoring State
  const [checkingResources, setCheckingResources] = useState<Set<number>>(new Set());
  const [showCheckHistoryModal, setShowCheckHistoryModal] = useState(false);
  const [resourceCheckHistory, setResourceCheckHistory] = useState<ResourceCheck[]>([]);
  const [selectedResourceForHistory, setSelectedResourceForHistory] = useState<Resource | null>(null);

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
      fetchResources();
      if (user.is_admin) {
        fetchAllAccessRequests();
        fetchPendingAccessRequests();
      } else {
        fetchMyAccessRequests();
      }
    }
  }, [user, activeTab]);

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
        if (response.status === 401) {
          localStorage.removeItem('token');
          router.push('/login');
          return;
        }
        throw new Error(data.error || 'Failed to fetch user data');
      }

      setUser(data);
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const fetchResources = async () => {
    try {
      const token = localStorage.getItem('token');
      const queryParams = new URLSearchParams();
      if (resourcesSearch) queryParams.append('q', resourcesSearch);
      if (resourcesTypeFilter) queryParams.append('type', resourcesTypeFilter);
      if (resourcesCriticalityFilter) queryParams.append('criticality', resourcesCriticalityFilter);
      queryParams.append('limit', '100');

      const response = await fetch(`/api/resources?${queryParams.toString()}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setResources(data.items || []);
      } else {
        const errorData = await response.json();
        console.error('Failed to fetch resources:', errorData.error);
      }
    } catch (err) {
      console.error('Failed to fetch resources:', err);
    }
  };

  const fetchCredentials = async (resourceId: number) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/resources/${resourceId}/credentials`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setCredentials(data);
      } else {
        console.error('Failed to fetch credentials');
      }
    } catch (err) {
      console.error('Failed to fetch credentials:', err);
    }
  };

  

  const validatePrivateKey = (privateKey: string): boolean => {
  if (!privateKey) return false;
  
  // Check for proper BEGIN and END markers
  const hasBeginMarker = privateKey.includes('-----BEGIN');
  const hasEndMarker = privateKey.includes('-----END');
  const hasKeyContent = privateKey.length > 100; // Basic length check
  
  if (!hasBeginMarker || !hasEndMarker) {
    console.error('Private key missing BEGIN/END markers');
    return false;
  }
  
  if (!hasKeyContent) {
    console.error('Private key too short');
    return false;
  }
  
  return true;
};

const handleCreateCredential = async (e: React.FormEvent) => {
  e.preventDefault();
  if (!selectedResourceForCredential) return;

  setSubmitting(true);
  setError('');

  try {
    // Basic validation
    if (!newCredential.name.trim()) {
      throw new Error('Credential name is required');
    }
    if (!newCredential.username.trim()) {
      throw new Error('Username is required');
    }
    if (newCredential.type === 'password' && !newCredential.password) {
      throw new Error('Password is required for password type credentials');
    }
    if (newCredential.type === 'ssh_key' && !newCredential.private_key) {
      throw new Error('Private key is required for SSH key type credentials');
    }
    if (newCredential.type === 'ssh_key' && !validatePrivateKey(newCredential.private_key)) {
      throw new Error('Private key format is invalid. It should start with -----BEGIN and end with -----END');
    }

    const token = localStorage.getItem('token');
    
    // Prepare the request data - DO NOT base64 encode the private key!
    const requestData: any = {
      name: newCredential.name.trim(),
      type: newCredential.type,
      username: newCredential.username.trim(),
      resource_id: selectedResourceForCredential.id
    };

    // Only include password or private_key based on type
    if (newCredential.type === 'password') {
      requestData.password = newCredential.password;
    } else if (newCredential.type === 'ssh_key') {
      // Send the private key as raw text, NOT base64 encoded
      requestData.private_key = newCredential.private_key;
      
      // Debug: log the private key format
      console.log('Private key being sent:', requestData.private_key.substring(0, 100) + '...');
    }

    console.log('Sending credential data:', requestData);

    const response = await fetch(`/api/resources/${selectedResourceForCredential.id}/credentials`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(requestData),
    });

    console.log('Response status:', response.status);
    
    if (!response.ok) {
      const errorData = await response.json();
      console.error('Error response:', errorData);
      
      let errorMessage = 'Failed to create credential';
      if (errorData.detail) {
        if (Array.isArray(errorData.detail)) {
          errorMessage = errorData.detail.map((err: any) => err.msg).join(', ');
        } else if (typeof errorData.detail === 'string') {
          errorMessage = errorData.detail;
        } else if (errorData.detail.msg) {
          errorMessage = errorData.detail.msg;
        }
      } else if (errorData.error) {
        errorMessage = errorData.error;
      }
      
      throw new Error(errorMessage);
    }

    const result = await response.json();
    console.log('Success response:', result);

    setShowCredentialModal(false);
    setNewCredential({
      name: '',
      type: 'password',
      username: '',
      password: '',
      private_key: ''
    });
    setSuccess('Credential created successfully!');
    
    // Refresh credentials list
    fetchCredentials(selectedResourceForCredential.id);
    
    setTimeout(() => setSuccess(''), 3000);
  } catch (err: any) {
    console.error('Error in handleCreateCredential:', err);
    setError(err.message || 'Failed to create credential');
  } finally {
    setSubmitting(false);
  }
};

  const handleDeleteCredential = async (credentialId: number, resourceId: number) => {
  try {
    const token = localStorage.getItem('token');
    const response = await fetch(`/api/resources/${resourceId}/credentials/${credentialId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Failed to delete credential');
    }

    setSuccess('Credential deleted successfully!');
    
    // Refresh credentials list
    if (selectedResourceForCredential) {
      await fetchCredentials(selectedResourceForCredential.id);
    }
    
    setTimeout(() => setSuccess(''), 3000);
  } catch (err: any) {
    setError(err.message || 'Failed to delete credential');
  }
};

  const openCredentialModal = async (resource: Resource) => {
    setSelectedResourceForCredential(resource);
    setShowCredentialModal(true);
    await fetchCredentials(resource.id);
  };

  // Health Monitoring Functions
  const checkResourceHealth = async (resourceId: number) => {
    setCheckingResources(prev => new Set(prev).add(resourceId));
    
    try {
      const response = await fetch('/api/resources', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          action: 'check',
          resourceId: resourceId
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to check resource health');
      }

      const result: HealthCheckResponse = await response.json();
      
      // Update the resource in the local state
      setResources(prev => prev.map(resource => 
        resource.id === resourceId 
          ? { 
              ...resource, 
              is_online: result.is_online, 
              last_checked_at: result.checked_at 
            }
          : resource
      ));

      setSuccess(`Resource is ${result.is_online ? 'online' : 'offline'}`);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to check resource health');
    } finally {
      setCheckingResources(prev => {
        const newSet = new Set(prev);
        newSet.delete(resourceId);
        return newSet;
      });
    }
  };

  

  const checkAllResourcesHealth = async () => {
    setCheckingResources(new Set(resources.map(r => r.id)));
    
    try {
      const response = await fetch('/api/resources', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          action: 'check-all'
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to check all resources');
      }

      const result = await response.json();
      
      // Update resources with new status
      setResources(prev => prev.map(resource => {
        const checkResult = result.results.find((r: any) => r.resource_id === resource.id);
        if (checkResult) {
          return {
            ...resource,
            is_online: checkResult.is_online,
            last_checked_at: checkResult.checked_at
          };
        }
        return resource;
      }));

      setSuccess(`Checked ${result.total_checked} resources: ${result.online_count} online, ${result.offline_count} offline`);
      setTimeout(() => setSuccess(''), 5000);
    } catch (err: any) {
      setError(err.message || 'Failed to check all resources');
    } finally {
      setCheckingResources(new Set());
    }
  };

  const viewCheckHistory = async (resource: Resource) => {
    setSelectedResourceForHistory(resource);
    setLoading(true);
    
    try {
      const response = await fetch('/api/resources', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          action: 'check-history',
          resourceId: resource.id
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to fetch check history');
      }

      const history = await response.json();
      setResourceCheckHistory(history);
      setShowCheckHistoryModal(true);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch check history');
    } finally {
      setLoading(false);
    }
  };

  // Status Badge Component
  const StatusBadge = ({ resource }: { resource: Resource }) => {
    const isChecking = checkingResources.has(resource.id);
    
    if (isChecking) {
      return (
        <span className="px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800 flex items-center">
          <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-blue-600 mr-1"></div>
          Checking...
        </span>
      );
    }
    
    if (!resource.last_checked_at) {
      return (
        <span className="px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
          Not Checked
        </span>
      );
    }
    
    const baseClasses = "px-2 py-1 rounded-full text-xs font-medium whitespace-nowrap flex items-center";
    const statusClasses = resource.is_online 
      ? "bg-green-100 text-green-800" 
      : "bg-red-100 text-red-800";
    
    return (
      <span className={`${baseClasses} ${statusClasses}`}>
        <div className={`w-2 h-2 rounded-full mr-1 ${resource.is_online ? 'bg-green-500' : 'bg-red-500'}`}></div>
        {resource.is_online ? 'Online' : 'Offline'}
      </span>
    );
  };

  const handleCreateResource = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError('');

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/resources', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          action: 'create',
          ...newResource
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to create resource');
      }

      setShowCreateResourceModal(false);
      setNewResource({
        name: '',
        type: 'ssh',
        hostname: '',
        port: undefined,
        description: '',
        criticality: 'medium'
      });
      setSuccess('Resource created successfully!');
      fetchResources();
      
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to create resource');
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpdateResource = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedResource) return;

    setSubmitting(true);
    setError('');

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/resources', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          action: 'update',
          resourceId: selectedResource.id,
          ...editResource
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to update resource');
      }

      setShowEditResourceModal(false);
      setSelectedResource(null);
      setEditResource({});
      setSuccess('Resource updated successfully!');
      fetchResources();
      
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to update resource');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteResource = async () => {
    if (!selectedResource) return;

    setSubmitting(true);
    setError('');

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/resources', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          action: 'delete',
          resourceId: selectedResource.id,
          force: deleteForce
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        if (errorData.details) {
          setDeleteDependencies(errorData.details);
          throw new Error(errorData.error || 'Resource has dependencies');
        }
        throw new Error(errorData.error || 'Failed to delete resource');
      }

      setShowDeleteResourceModal(false);
      setSelectedResource(null);
      setDeleteForce(false);
      setDeleteDependencies(null);
      setSuccess('Resource deleted successfully!');
      fetchResources();
      
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to delete resource');
    } finally {
      setSubmitting(false);
    }
  };

  const openEditResourceModal = (resource: Resource) => {
    setSelectedResource(resource);
    setEditResource({
      name: resource.name,
      type: resource.type,
      hostname: resource.hostname,
      port: resource.port,
      description: resource.description,
      criticality: resource.criticality
    });
    setShowEditResourceModal(true);
  };

  const openDeleteResourceModal = (resource: Resource) => {
    setSelectedResource(resource);
    setDeleteForce(false);
    setDeleteDependencies(null);
    setShowDeleteResourceModal(true);
  };

  const fetchMyAccessRequests = async () => {
    try {
      const response = await fetch('/api/access-requests?action=my-requests', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setMyAccessRequests(data);
      } else {
        const errorData = await response.json();
        console.error('Failed to fetch my access requests:', errorData.error);
      }
    } catch (err) {
      console.error('Failed to fetch my access requests:', err);
    }
  };

  const fetchAllAccessRequests = async () => {
    try {
      const response = await fetch('/api/access-requests', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setAllAccessRequests(data);
      } else {
        const errorData = await response.json();
        console.error('Failed to fetch all access requests:', errorData.error);
      }
    } catch (err) {
      console.error('Failed to fetch all access requests:', err);
    }
  };

  const fetchPendingAccessRequests = async () => {
    try {
      const response = await fetch('/api/access-requests?action=pending', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setPendingAccessRequests(data);
      } else {
        const errorData = await response.json();
        console.error('Failed to fetch pending access requests:', errorData.error);
      }
    } catch (err) {
      console.error('Failed to fetch pending access requests:', err);
    }
  };

  const fetchAuditLogs = async () => {
    if (!user?.is_admin) return;
    
    setLoadingAuditLogs(true);
    try {
      const queryParams = new URLSearchParams();
      if (auditFilters.user_id) queryParams.append('user_id', auditFilters.user_id);
      if (auditFilters.action_type) queryParams.append('action_type', auditFilters.action_type);
      if (auditFilters.severity) queryParams.append('severity', auditFilters.severity);
      if (auditFilters.start_date) queryParams.append('start_date', auditFilters.start_date);
      if (auditFilters.end_date) queryParams.append('end_date', auditFilters.end_date);

      const response = await fetch(`/api/audit-logs?${queryParams.toString()}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setAuditLogs(data);
      } else {
        const errorData = await response.json();
        console.error('Failed to fetch audit logs:', errorData.error);
      }
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setLoadingAuditLogs(false);
    }
  };

  const fetchAuditStats = async () => {
    if (!user?.is_admin) return;

    try {
      const response = await fetch('/api/audit-logs?action=stats', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setAuditStats(data);
      } else {
        const errorData = await response.json();
        console.error('Failed to fetch audit stats:', errorData.error);
      }
    } catch (err) {
      console.error('Failed to fetch audit stats:', err);
    }
  };

  useEffect(() => {
    if (user?.is_admin && activeTab === 'audit') {
      fetchAuditLogs();
      fetchAuditStats();
    }
  }, [user, activeTab]);

  const handleAuditFilterChange = (key: string, value: string) => {
    setAuditFilters(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const clearAuditFilters = () => {
    setAuditFilters({
      user_id: '',
      action_type: '',
      severity: '',
      start_date: '',
      end_date: ''
    });
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('refresh_token');
    router.push('/');
  };

  const handleCreateRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);

    try {
      const response = await fetch('/api/access-requests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          action: 'create',
          resource_id: parseInt(newRequest.resource_id),
          reason: newRequest.reason,
          expires_at: newRequest.expires_at
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to create access request');
      }

      setShowRequestModal(false);
      setNewRequest({ resource_id: '', reason: '', expires_at: '' });
      
      // Refresh the appropriate requests list
      if (user?.is_admin) {
        fetchAllAccessRequests();
        fetchPendingAccessRequests();
      } else {
        fetchMyAccessRequests();
      }

      setSuccess('Access request created successfully!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to create access request');
    } finally {
      setSubmitting(false);
    }
  };

  const handleApproveRequest = async (requestId: number) => {
    try {
      const response = await fetch('/api/access-requests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          action: 'approve',
          requestId: requestId
        }),
      });

      if (response.ok) {
        fetchPendingAccessRequests();
        fetchAllAccessRequests();
        setSuccess('Access request approved successfully!');
        setTimeout(() => setSuccess(''), 3000);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to approve request');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to approve request');
    }
  };

  const handleRejectRequest = async (requestId: number) => {
    try {
      const response = await fetch('/api/access-requests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          action: 'reject',
          requestId: requestId
        }),
      });

      if (response.ok) {
        fetchPendingAccessRequests();
        fetchAllAccessRequests();
        setSuccess('Access request rejected successfully!');
        setTimeout(() => setSuccess(''), 3000);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to reject request');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to reject request');
    }
  };

  const getStatusBadge = (status: string) => {
    const baseClasses = "px-2 py-1 rounded-full text-xs font-medium whitespace-nowrap";
    switch (status) {
      case 'pending':
        return `${baseClasses} bg-yellow-100 text-yellow-800`;
      case 'approved':
        return `${baseClasses} bg-green-100 text-green-800`;
      case 'rejected':
        return `${baseClasses} bg-red-100 text-red-800`;
      case 'expired':
        return `${baseClasses} bg-gray-100 text-gray-800`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800`;
    }
  };

  const getCriticalityBadge = (criticality: string) => {
    const baseClasses = "px-2 py-1 rounded-full text-xs font-medium";
    switch (criticality) {
      case 'high':
        return `${baseClasses} bg-red-100 text-red-800`;
      case 'medium':
        return `${baseClasses} bg-yellow-100 text-yellow-800`;
      case 'low':
        return `${baseClasses} bg-green-100 text-green-800`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800`;
    }
  };

  const getTypeBadge = (type: string) => {
    const baseClasses = "px-2 py-1 rounded-full text-xs font-medium";
    switch (type) {
      case 'ssh':
        return `${baseClasses} bg-blue-100 text-blue-800`;
      case 'rdp':
        return `${baseClasses} bg-purple-100 text-purple-800`;
      case 'db':
        return `${baseClasses} bg-green-100 text-green-800`;
      case 'api':
        return `${baseClasses} bg-indigo-100 text-indigo-800`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800`;
    }
  };

  const getSeverityBadge = (severity: string) => {
    const baseClasses = "px-2 py-1 rounded-full text-xs font-medium";
    switch (severity) {
      case 'critical':
        return `${baseClasses} bg-red-100 text-red-800`;
      case 'warning':
        return `${baseClasses} bg-yellow-100 text-yellow-800`;
      case 'info':
        return `${baseClasses} bg-blue-100 text-blue-800`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800`;
    }
  };

  const formatAuditDetails = (details: any) => {
    if (!details) return '-';
    if (typeof details === 'string') return details;
    return JSON.stringify(details, null, 2);
  };

  // Safe getter for audit stats
  const getSeverityCount = (severity: string) => {
    if (!auditStats?.severity_stats) return 0;
    return auditStats.severity_stats[severity] || 0;
  };

  // Helper function to check if user has access to a resource
  const hasAccessToResource = (resourceId: number) => {
    if (user?.is_admin) return true;
    
    const request = myAccessRequests.find(req => 
      req.resource_id === resourceId && 
      req.status === 'approved' && 
      new Date(req.expires_at) > new Date()
    );
    
    return !!request;
  };

  // Responsive table component for mobile
  const MobileRequestCard = ({ request, showActions = false }: { request: AccessRequest, showActions?: boolean }) => (
    <div className="bg-white rounded-lg shadow-sm border p-4 mb-3">
      <div className="space-y-2">
        <div className="flex justify-between items-start">
          <div>
            <h4 className="font-semibold text-gray-900 text-sm">{request.resource?.name}</h4>
            <p className="text-xs text-gray-500">{request.resource?.hostname}</p>
          </div>
          <span className={getStatusBadge(request.status)}>
            {request.status}
          </span>
        </div>
        
        <div className="text-sm text-gray-600">
          <p className="truncate">{request.reason || 'No reason provided'}</p>
        </div>
        
        <div className="grid grid-cols-2 gap-2 text-xs text-gray-500">
          <div>
            <span className="font-medium">Requested:</span>
            <br />
            {new Date(request.requested_at).toLocaleDateString()}
          </div>
          <div>
            <span className="font-medium">Expires:</span>
            <br />
            {new Date(request.expires_at).toLocaleDateString()}
          </div>
        </div>

        {showActions && request.status === 'pending' && (
          <div className="flex space-x-2 pt-2">
            <button
              onClick={() => handleApproveRequest(request.id)}
              className="flex-1 bg-green-600 hover:bg-green-700 text-white px-3 py-2 rounded text-sm"
            >
              Approve
            </button>
            <button
              onClick={() => handleRejectRequest(request.id)}
              className="flex-1 bg-red-600 hover:bg-red-700 text-white px-3 py-2 rounded text-sm"
            >
              Reject
            </button>
          </div>
        )}
      </div>
    </div>
  );

  // Mobile Resource Card for responsive view
  const MobileResourceCard = ({ resource, showAdminActions = false }: { resource: Resource, showAdminActions?: boolean }) => {
    const request = myAccessRequests.find(req => req.resource_id === resource.id);
    const hasAccess = hasAccessToResource(resource.id);

    return (
      <div className="bg-white rounded-lg shadow-sm border p-4 mb-3">
        <div className="space-y-3">
          <div className="flex justify-between items-start">
            <div>
              <h4 className="font-semibold text-gray-900 text-sm">{resource.name}</h4>
              <p className="text-xs text-gray-500">{resource.hostname}:{resource.port || 'default'}</p>
            </div>
            <div className="flex flex-col items-end space-y-1">
              <span className={getTypeBadge(resource.type)}>
                {resource.type.toUpperCase()}
              </span>
              <span className={getCriticalityBadge(resource.criticality)}>
                {resource.criticality}
              </span>
            </div>
          </div>
          
          <div className="flex justify-between items-center">
            <StatusBadge resource={resource} />
            <span className="text-xs text-gray-500">
              {resource.last_checked_at 
                ? new Date(resource.last_checked_at).toLocaleString()
                : 'Never checked'
              }
            </span>
          </div>
          
          {resource.description && (
            <div className="text-sm text-gray-600">
              <p className="line-clamp-2">{resource.description}</p>
            </div>
          )}
          
          <div className="flex space-x-2">
            {!showAdminActions ? (
              <>
                {hasAccess && resource.type === 'ssh' && (
                  <button
                    onClick={() => router.push(`/terminal/${resource.id}`)}
                    className="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 px-3 rounded text-sm font-medium"
                  >
                    Connect
                  </button>
                )}
                {!hasAccess && (
                  <button
                    onClick={() => {
                      setNewRequest({
                        ...newRequest,
                        resource_id: resource.id.toString()
                      });
                      setShowRequestModal(true);
                    }}
                    className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 px-3 rounded text-sm font-medium"
                  >
                    Request Access
                  </button>
                )}
              </>
            ) : (
              <>
                <button
                  onClick={() => checkResourceHealth(resource.id)}
                  disabled={checkingResources.has(resource.id)}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 px-3 rounded text-sm font-medium disabled:opacity-50"
                >
                  {checkingResources.has(resource.id) ? 'Checking...' : 'Check Health'}
                </button>
                <button
                  onClick={() => viewCheckHistory(resource)}
                  className="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 px-3 rounded text-sm font-medium"
                >
                  History
                </button>
                <button
                  onClick={() => openEditResourceModal(resource)}
                  className="flex-1 bg-yellow-600 hover:bg-yellow-700 text-white py-2 px-3 rounded text-sm font-medium"
                >
                  Edit
                </button>
                <button
                  onClick={() => openCredentialModal(resource)}
                  className="flex-1 bg-purple-600 hover:bg-purple-700 text-white py-2 px-3 rounded text-sm font-medium"
                >
                  Credentials
                </button>
                <button
                  onClick={() => openDeleteResourceModal(resource)}
                  className="flex-1 bg-red-600 hover:bg-red-700 text-white py-2 px-3 rounded text-sm font-medium"
                >
                  Delete
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading your dashboard...</p>
        </div>
      </div>
    );
  }

  if (error && !user) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="bg-white p-6 rounded-lg shadow-md max-w-md w-full mx-4">
          <h2 className="text-xl font-semibold text-red-600 mb-4">Error</h2>
          <p className="text-gray-700 mb-6">{error}</p>
          <button
            onClick={() => router.push('/login')}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700"
          >
            Go to Login
          </button>
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
              <h1 className="text-xl font-semibold text-gray-800">OpenPAM</h1>
              <span className="ml-2 hidden sm:inline text-sm text-gray-600">Dashboard</span>
            </div>
            
            {/* Mobile menu button */}
            <div className="flex items-center space-x-4">
              <div className="hidden sm:block text-right">
                <p className="text-sm text-gray-600">Welcome, {user?.username}</p>
                {user?.is_admin && (
                  <span className="inline-block mt-1 px-2 py-1 text-xs font-medium bg-purple-100 text-purple-800 rounded-full">
                    Administrator
                  </span>
                )}
              </div>
              
              <button
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                className="sm:hidden p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100"
              >
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
              
              <button
                onClick={handleLogout}
                className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-3 sm:px-4 rounded text-sm"
              >
                <span className="hidden sm:inline">Logout</span>
                <span className="sm:hidden">Exit</span>
              </button>
            </div>
          </div>

          {/* Mobile user info */}
          <div className={`sm:hidden pb-4 ${isMobileMenuOpen ? 'block' : 'hidden'}`}>
            <p className="text-sm text-gray-600">Welcome, {user?.username}</p>
            {user?.is_admin && (
              <span className="inline-block mt-1 px-2 py-1 text-xs font-medium bg-purple-100 text-purple-800 rounded-full">
                Administrator
              </span>
            )}
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav className="flex space-x-8 overflow-x-auto">
            <button
              onClick={() => setActiveTab('overview')}
              className={`py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap ${
                activeTab === 'overview'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Overview
            </button>
            
            <button
              onClick={() => setActiveTab('resources')}
              className={`py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap ${
                activeTab === 'resources'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Resources
            </button>
            
            {!user?.is_admin && (
              <button
                onClick={() => setActiveTab('requests')}
                className={`py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap ${
                  activeTab === 'requests'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                My Access Requests
              </button>
            )}
            
            {user?.is_admin && (
              <>
                <button
                  onClick={() => setActiveTab('admin')}
                  className={`py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap ${
                    activeTab === 'admin'
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  Admin Panel
                </button>
                <button
                  onClick={() => setActiveTab('audit')}
                  className={`py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap ${
                    activeTab === 'audit'
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  Audit History
                </button>
              </>
            )}
          </nav>
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8 py-4 sm:py-8">
        {error && (
          <div className="mb-4 sm:mb-6 p-3 sm:p-4 bg-red-50 text-red-700 rounded-md text-sm">
            {error}
          </div>
        )}

        {success && (
          <div className="mb-4 sm:mb-6 p-3 sm:p-4 bg-green-50 text-green-700 rounded-md text-sm">
            {success}
          </div>
        )}

        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div>
            <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6 mb-6 sm:mb-8">
              <h2 className="text-xl sm:text-2xl font-bold mb-3 sm:mb-4 text-gray-800">
                Welcome to OpenPAM, {user?.username}!
              </h2>
              <p className="text-gray-600 text-sm sm:text-base">
                {user?.is_admin 
                  ? "You are logged in as an administrator. You can manage access requests and system resources."
                  : "You have successfully logged into the OpenPAM dashboard. From here you can request privileged access to resources."
                }
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
              <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6">
                <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-3 text-gray-800">Available Resources</h3>
                <p className="text-gray-600 text-sm sm:text-base mb-3 sm:mb-4">Browse and request access to available resources.</p>
                <button 
                  onClick={() => setActiveTab('resources')}
                  className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white py-2 px-3 sm:px-4 rounded text-sm"
                >
                  View Resources
                </button>
              </div>

              <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6">
                <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-3 text-gray-800">
                  {user?.is_admin ? 'Access Management' : 'Access Requests'}
                </h3>
                <p className="text-gray-600 text-sm sm:text-base mb-3 sm:mb-4">
                  {user?.is_admin 
                    ? 'Review and manage access requests from users.'
                    : 'Request and manage just-in-time access to resources.'
                  }
                </p>
                <button 
                  onClick={() => setActiveTab(user?.is_admin ? 'admin' : 'requests')}
                  className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white py-2 px-3 sm:px-4 rounded text-sm"
                >
                  {user?.is_admin ? 'Manage Requests' : 'View Requests'}
                </button>
              </div>

              <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6">
                <h3 className="text-base sm:text-lg font-semibold mb-2 sm:mb-3 text-gray-800">Session History</h3>
                <p className="text-gray-600 text-sm sm:text-base mb-3 sm:mb-4">Review your past privileged sessions.</p>
                <button className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white py-2 px-3 sm:px-4 rounded text-sm">
                  View History
                </button>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="mt-6 sm:mt-8 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
              {user?.is_admin ? (
                <>
                  <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6">
                    <h4 className="text-base sm:text-lg font-semibold text-gray-800 mb-2">Pending Requests</h4>
                    <p className="text-2xl sm:text-3xl font-bold text-yellow-600">{pendingAccessRequests.length}</p>
                    <p className="text-xs sm:text-sm text-gray-600 mt-2">Awaiting approval</p>
                  </div>
                  <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6">
                    <h4 className="text-base sm:text-lg font-semibold text-gray-800 mb-2">Total Requests</h4>
                    <p className="text-2xl sm:text-3xl font-bold text-blue-600">{allAccessRequests.length}</p>
                    <p className="text-xs sm:text-sm text-gray-600 mt-2">All time</p>
                  </div>
                  <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6">
                    <h4 className="text-base sm:text-lg font-semibold text-gray-800 mb-2">Active Resources</h4>
                    <p className="text-2xl sm:text-3xl font-bold text-green-600">{resources.length}</p>
                    <p className="text-xs sm:text-sm text-gray-600 mt-2">Available for access</p>
                  </div>
                </>
              ) : (
                <>
                  <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6">
                    <h4 className="text-base sm:text-lg font-semibold text-gray-800 mb-2">My Requests</h4>
                    <p className="text-2xl sm:text-3xl font-bold text-blue-600">{myAccessRequests.length}</p>
                    <p className="text-xs sm:text-sm text-gray-600 mt-2">Total requests</p>
                  </div>
                  <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6">
                    <h4 className="text-base sm:text-lg font-semibold text-gray-800 mb-2">Pending</h4>
                    <p className="text-2xl sm:text-3xl font-bold text-yellow-600">
                      {myAccessRequests.filter(req => req.status === 'pending').length}
                    </p>
                    <p className="text-xs sm:text-sm text-gray-600 mt-2">Awaiting approval</p>
                  </div>
                  <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-4 sm:p-6">
                    <h4 className="text-base sm:text-lg font-semibold text-gray-800 mb-2">Approved</h4>
                    <p className="text-2xl sm:text-3xl font-bold text-green-600">
                      {myAccessRequests.filter(req => req.status === 'approved').length}
                    </p>
                    <p className="text-xs sm:text-sm text-gray-600 mt-2">Active access</p>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {/* Resources Tab - For all users */}
        {activeTab === 'resources' && (
          <div>
            <div className="mb-6">
              <h2 className="text-xl sm:text-2xl font-bold text-gray-800 mb-4">
                {user?.is_admin ? 'Resource Management' : 'Available Resources'}
              </h2>
              
              {/* Search and Filters */}
              <div className="bg-white rounded-lg shadow-sm p-4 sm:p-6 mb-6">
                <div className="flex flex-col sm:flex-row gap-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      placeholder="Search resources by name or hostname..."
                      value={resourcesSearch}
                      onChange={(e) => setResourcesSearch(e.target.value)}
                      className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div className="w-full sm:w-48">
                    <select
                      value={resourcesTypeFilter}
                      onChange={(e) => setResourcesTypeFilter(e.target.value)}
                      className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="">All Types</option>
                      <option value="ssh">SSH</option>
                      <option value="rdp">RDP</option>
                      <option value="db">Database</option>
                      <option value="api">API</option>
                      <option value="web">Web</option>
                      <option value="service">Service</option>
                    </select>
                  </div>
                  <div className="w-full sm:w-48">
                    <select
                      value={resourcesCriticalityFilter}
                      onChange={(e) => setResourcesCriticalityFilter(e.target.value)}
                      className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="">All Criticalities</option>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </div>
                  {user?.is_admin && (
                    <button
                      onClick={() => setShowCreateResourceModal(true)}
                      className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded text-sm"
                    >
                      + New Resource
                    </button>
                  )}
                </div>
              </div>

              {/* Resources Grid/Table */}
              <div className="bg-white rounded-lg shadow-sm overflow-hidden">
                {resources.length > 0 ? (
                  <>
                    {/* Desktop Table */}
                    <div className="hidden sm:block">
                      <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                          <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Name
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Type
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Hostname
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Status
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Last Checked
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Criticality
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Actions
                            </th>
                          </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                          {resources.map((resource) => {
                            const request = myAccessRequests.find(req => req.resource_id === resource.id);
                            const hasAccess = hasAccessToResource(resource.id);

                            return (
                              <tr key={resource.id} className="hover:bg-gray-50">
                                <td className="px-6 py-4 whitespace-nowrap">
                                  <div className="text-sm font-medium text-gray-900">
                                    {resource.name}
                                  </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                  <span className={getTypeBadge(resource.type)}>
                                    {resource.type.toUpperCase()}
                                  </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                  {resource.hostname}:{resource.port || '-'}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                  <StatusBadge resource={resource} />
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                  {resource.last_checked_at 
                                    ? new Date(resource.last_checked_at).toLocaleString()
                                    : 'Never'
                                  }
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                  <span className={getCriticalityBadge(resource.criticality)}>
                                    {resource.criticality}
                                  </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                  <div className="flex space-x-2">
                                    {user?.is_admin ? (
                                      <>
                                        <button
                                          onClick={() => checkResourceHealth(resource.id)}
                                          disabled={checkingResources.has(resource.id)}
                                          className="text-blue-600 hover:text-blue-900 disabled:opacity-50"
                                          title="Check Health"
                                        >
                                          🔍
                                        </button>
                                        <button
                                          onClick={() => viewCheckHistory(resource)}
                                          className="text-green-600 hover:text-green-900"
                                          title="View History"
                                        >
                                          📊
                                        </button>
                                        <button
                                          onClick={() => openEditResourceModal(resource)}
                                          className="text-yellow-600 hover:text-yellow-900"
                                          title="Edit"
                                        >
                                          ✏️
                                        </button>
                                        {user?.is_admin && (
                                          <button
                                            onClick={() => openCredentialModal(resource)}
                                            className="text-purple-600 hover:text-purple-900 ml-2"
                                            title="Manage Credentials"
                                          >
                                            🔑
                                          </button>
                                        )}
                                        <button
                                          onClick={() => openDeleteResourceModal(resource)}
                                          className="text-red-600 hover:text-red-900"
                                          title="Delete"
                                        >
                                          🗑️
                                        </button>
                                        {hasAccess && resource.type === 'ssh' && (
                                          <button
                                            onClick={() => router.push(`/terminal/${resource.id}`)}
                                            className="text-green-600 hover:text-green-900"
                                            title="Connect via SSH"
                                          >
                                            🔌 Connect
                                          </button>
                                        )}
                                      </>
                                    ) : (
                                      <>
                                        {hasAccess && resource.type === 'ssh' && (
                                          <button
                                            onClick={() => router.push(`/terminal/${resource.id}`)}
                                            className="text-green-600 hover:text-green-900 ml-2"
                                            title="Connect via SSH"
                                          >
                                            🔌
                                          </button>
                                        )}
                                        {!hasAccess && (
                                          <button
                                            onClick={() => {
                                              setNewRequest({
                                                ...newRequest,
                                                resource_id: resource.id.toString()
                                              });
                                              setShowRequestModal(true);
                                            }}
                                            className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm"
                                          >
                                            Request Access
                                          </button>
                                        )}
                                      </>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>

                    {/* Check All Button for Admin */}
                    {user?.is_admin && (
                      <div className="p-4 border-t">
                        <button
                          onClick={checkAllResourcesHealth}
                          disabled={checkingResources.size > 0}
                          className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
                        >
                          {checkingResources.size > 0 ? 'Checking...' : 'Check All Resources'}
                        </button>
                      </div>
                    )}

                    {/* Mobile Cards */}
                    <div className="sm:hidden p-4">
                      {resources.map((resource) => (
                        <MobileResourceCard 
                          key={resource.id} 
                          resource={resource} 
                          showAdminActions={user?.is_admin || false}
                        />
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="text-center py-12">
                    <div className="text-gray-400 mb-4">
                      <svg className="mx-auto h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                      </svg>
                    </div>
                    <h3 className="text-lg font-medium text-gray-900 mb-2">No resources found</h3>
                    <p className="text-gray-500">No resources match your current filters.</p>
                    {user?.is_admin && (
                      <button
                        onClick={() => setShowCreateResourceModal(true)}
                        className="mt-4 bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                      >
                        Create Resource
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* My Access Requests Tab - Only for non-admin users */}
        {activeTab === 'requests' && !user?.is_admin && (
          <div>
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4 sm:mb-6">
              <h2 className="text-xl sm:text-2xl font-bold text-gray-800">My Access Requests</h2>
              <button
                onClick={() => setShowRequestModal(true)}
                className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded text-sm"
              >
                + New Request
              </button>
            </div>

            <div className="bg-white rounded-lg shadow-sm sm:shadow-md overflow-hidden">
              {myAccessRequests.length > 0 ? (
                <>
                  {/* Desktop Table */}
                  <div className="hidden sm:block">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Resource
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Reason
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Status
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Requested
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Expires
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {myAccessRequests.map((request) => (
                          <tr key={request.id} className="hover:bg-gray-50">
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-medium text-gray-900">
                                {request.resource?.name}
                              </div>
                              <div className="text-sm text-gray-500">
                                {request.resource?.hostname}
                              </div>
                            </td>
                            <td className="px-4 lg:px-6 py-4">
                              <div className="text-sm text-gray-900 max-w-xs truncate">
                                {request.reason || 'No reason provided'}
                              </div>
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap">
                              <span className={getStatusBadge(request.status)}>
                                {request.status}
                              </span>
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {new Date(request.requested_at).toLocaleDateString()}
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {new Date(request.expires_at).toLocaleDateString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Mobile Cards */}
                  <div className="sm:hidden p-4">
                    {myAccessRequests.map((request) => (
                      <MobileRequestCard key={request.id} request={request} />
                    ))}
                  </div>
                </>
              ) : (
                <div className="text-center py-8 sm:py-12">
                  <div className="text-gray-400 mb-4">
                    <svg className="mx-auto h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No access requests</h3>
                  <p className="text-gray-500">You haven't created any access requests yet.</p>
                  <button
                    onClick={() => setShowRequestModal(true)}
                    className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                  >
                    Create your first request
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Admin Panel Tab - Only for admin users */}
        {activeTab === 'admin' && user?.is_admin && (
          <div>
            <div className="mb-4 sm:mb-6">
              <h2 className="text-xl sm:text-2xl font-bold text-gray-800">Admin Panel</h2>
            </div>

            {/* Pending Requests Section */}
            <div className="mb-6 sm:mb-8">
              <h3 className="text-lg sm:text-xl font-semibold mb-3 sm:mb-4 text-gray-800">Pending Approval Requests</h3>
              {pendingAccessRequests.length > 0 ? (
                <>
                  {/* Desktop Table */}
                  <div className="hidden sm:block bg-white rounded-lg shadow-md overflow-hidden">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            User
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Resource
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Reason
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Requested
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Expires
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Actions
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {pendingAccessRequests.map((request) => (
                          <tr key={request.id} className="hover:bg-gray-50">
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-medium text-gray-900">
                                {request.user?.username}
                              </div>
                              <div className="text-sm text-gray-500">
                                {request.user?.email}
                              </div>
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-medium text-gray-900">
                                {request.resource?.name}
                              </div>
                              <div className="text-sm text-gray-500">
                                {request.resource?.hostname}
                              </div>
                            </td>
                            <td className="px-4 lg:px-6 py-4">
                              <div className="text-sm text-gray-900 max-w-xs truncate">
                                {request.reason || 'No reason provided'}
                              </div>
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {new Date(request.requested_at).toLocaleDateString()}
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {new Date(request.expires_at).toLocaleDateString()}
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm font-medium">
                              <div className="flex space-x-2">
                                <button
                                  onClick={() => handleApproveRequest(request.id)}
                                  className="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded text-xs sm:text-sm"
                                >
                                  Approve
                                </button>
                                <button
                                  onClick={() => handleRejectRequest(request.id)}
                                  className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-xs sm:text-sm"
                                >
                                  Reject
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Mobile Cards */}
                  <div className="sm:hidden space-y-3">
                    {pendingAccessRequests.map((request) => (
                      <MobileRequestCard key={request.id} request={request} showActions={true} />
                    ))}
                  </div>
                </>
              ) : (
                <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-6 sm:p-8 text-center">
                  <div className="text-gray-400 mb-4">
                    <svg className="mx-auto h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No pending requests</h3>
                  <p className="text-gray-500">All access requests have been processed.</p>
                </div>
              )}
            </div>

            {/* All Requests Section */}
            <div>
              <h3 className="text-lg sm:text-xl font-semibold mb-3 sm:mb-4 text-gray-800">All Access Requests</h3>
              {allAccessRequests.length > 0 ? (
                <>
                  {/* Desktop Table */}
                  <div className="hidden sm:block bg-white rounded-lg shadow-md overflow-hidden">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            User
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Resource
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Status
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Requested
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Expires
                          </th>
                          <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Approved By
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {allAccessRequests.map((request) => (
                          <tr key={request.id} className="hover:bg-gray-50">
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-medium text-gray-900">
                                {request.user?.username}
                              </div>
                              <div className="text-sm text-gray-500">
                                {request.user?.email}
                              </div>
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-medium text-gray-900">
                                {request.resource?.name}
                              </div>
                              <div className="text-sm text-gray-500">
                                {request.resource?.hostname}
                              </div>
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap">
                              <span className={getStatusBadge(request.status)}>
                                {request.status}
                              </span>
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {new Date(request.requested_at).toLocaleDateString()}
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {new Date(request.expires_at).toLocaleDateString()}
                            </td>
                            <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                              {request.approver?.username || '-'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Mobile Cards */}
                  <div className="sm:hidden space-y-3">
                    {allAccessRequests.map((request) => (
                      <MobileRequestCard key={request.id} request={request} />
                    ))}
                  </div>
                </>
              ) : (
                <div className="bg-white rounded-lg shadow-sm sm:shadow-md p-6 sm:p-8 text-center">
                  <div className="text-gray-400 mb-4">
                    <svg className="mx-auto h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No access requests</h3>
                  <p className="text-gray-500">No users have created access requests yet.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Audit History Tab - Only for admin users */}
        {activeTab === 'audit' && user?.is_admin && (
          <div>
            <div className="mb-6">
              <h2 className="text-xl sm:text-2xl font-bold text-gray-800 mb-4">Audit History</h2>
              
              {/* Audit Stats */}
              {auditStats && (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                  <div className="bg-white rounded-lg shadow-sm p-4">
                    <h4 className="text-sm font-medium text-gray-500 mb-1">Total Logs</h4>
                    <p className="text-2xl font-bold text-blue-600">{auditStats.total_logs}</p>
                  </div>
                  <div className="bg-white rounded-lg shadow-sm p-4">
                    <h4 className="text-sm font-medium text-gray-500 mb-1">Last 24h</h4>
                    <p className="text-2xl font-bold text-green-600">{auditStats.recent_activity_24h}</p>
                  </div>
                  <div className="bg-white rounded-lg shadow-sm p-4">
                    <h4 className="text-sm font-medium text-gray-500 mb-1">Warnings</h4>
                    <p className="text-2xl font-bold text-yellow-600">{getSeverityCount('warning')}</p>
                  </div>
                  <div className="bg-white rounded-lg shadow-sm p-4">
                    <h4 className="text-sm font-medium text-gray-500 mb-1">Critical</h4>
                    <p className="text-2xl font-bold text-red-600">{getSeverityCount('critical')}</p>
                  </div>
                </div>
              )}

              {/* Filters */}
              <div className="bg-white rounded-lg shadow-sm p-4 mb-6">
                <h3 className="text-lg font-semibold mb-4">Filters</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">User ID</label>
                    <input
                      type="number"
                      value={auditFilters.user_id}
                      onChange={(e) => handleAuditFilterChange('user_id', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                      placeholder="Filter by user ID"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Action Type</label>
                    <select
                      value={auditFilters.action_type}
                      onChange={(e) => handleAuditFilterChange('action_type', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                    >
                      <option value="">All Actions</option>
                      <option value="login">Login</option>
                      <option value="logout">Logout</option>
                      <option value="login_failed">Failed Login</option>
                      <option value="create_request">Create Request</option>
                      <option value="approve_request">Approve Request</option>
                      <option value="reject_request">Reject Request</option>
                      <option value="password_change">Password Change</option>
                      <option value="mfa_enabled">MFA Enabled</option>
                      <option value="mfa_disabled">MFA Disabled</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                    <select
                      value={auditFilters.severity}
                      onChange={(e) => handleAuditFilterChange('severity', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                    >
                      <option value="">All Severities</option>
                      <option value="info">Info</option>
                      <option value="warning">Warning</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Start Date</label>
                    <input
                      type="date"
                      value={auditFilters.start_date}
                      onChange={(e) => handleAuditFilterChange('start_date', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">End Date</label>
                    <input
                      type="date"
                      value={auditFilters.end_date}
                      onChange={(e) => handleAuditFilterChange('end_date', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm"
                    />
                  </div>
                </div>
                <div className="flex justify-end space-x-2 mt-4">
                  <button
                    onClick={clearAuditFilters}
                    className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                  >
                    Clear Filters
                  </button>
                  <button
                    onClick={fetchAuditLogs}
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
                  >
                    Apply Filters
                  </button>
                </div>
              </div>

              {/* Audit Logs Table */}
              <div className="bg-white rounded-lg shadow-sm overflow-hidden">
                {loadingAuditLogs ? (
                  <div className="text-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                    <p className="mt-2 text-gray-600">Loading audit logs...</p>
                  </div>
                ) : auditLogs.length > 0 ? (
                  <>
                    {/* Desktop Table */}
                    <div className="hidden sm:block">
                      <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                          <tr>
                            <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Timestamp
                            </th>
                            <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              User
                            </th>
                            <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Action
                            </th>
                            <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Type
                            </th>
                            <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Severity
                            </th>
                            <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              IP Address
                            </th>
                            <th className="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Details
                            </th>
                          </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                          {auditLogs.map((log) => (
                            <tr key={log.id} className="hover:bg-gray-50">
                              <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                {new Date(log.timestamp).toLocaleString()}
                              </td>
                              <td className="px-4 lg:px-6 py-4 whitespace-nowrap">
                                <div className="text-sm font-medium text-gray-900">
                                  {log.user?.username || log.admin_user?.username || 'System'}
                                </div>
                                <div className="text-sm text-gray-500">
                                  {log.user?.email || log.admin_user?.email || '-'}
                                </div>
                              </td>
                              <td className="px-4 lg:px-6 py-4">
                                <div className="text-sm text-gray-900 max-w-xs">
                                  {log.action}
                                </div>
                              </td>
                              <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                {log.action_type}
                              </td>
                              <td className="px-4 lg:px-6 py-4 whitespace-nowrap">
                                <span className={getSeverityBadge(log.severity)}>
                                  {log.severity}
                                </span>
                              </td>
                              <td className="px-4 lg:px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                {log.ip_address || '-'}
                              </td>
                              <td className="px-4 lg:px-6 py-4">
                                <div className="text-sm text-gray-500 max-w-xs truncate">
                                  {formatAuditDetails(log.details)}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {/* Mobile Cards */}
                    <div className="sm:hidden p-4 space-y-3">
                      {auditLogs.map((log) => (
                        <div key={log.id} className="bg-gray-50 rounded-lg p-4">
                          <div className="flex justify-between items-start mb-2">
                            <div>
                              <h4 className="font-semibold text-gray-900 text-sm">
                                {log.user?.username || log.admin_user?.username || 'System'}
                              </h4>
                              <p className="text-xs text-gray-500">{log.action_type}</p>
                            </div>
                            <span className={getSeverityBadge(log.severity)}>
                              {log.severity}
                            </span>
                          </div>
                          <p className="text-sm text-gray-700 mb-2">{log.action}</p>
                          <div className="grid grid-cols-2 gap-2 text-xs text-gray-500">
                            <div>
                              <span className="font-medium">Time:</span>
                              <br />
                              {new Date(log.timestamp).toLocaleString()}
                            </div>
                            <div>
                              <span className="font-medium">IP:</span>
                              <br />
                              {log.ip_address || '-'}
                            </div>
                          </div>
                          {log.details && (
                            <div className="mt-2">
                              <details className="text-xs">
                                <summary className="cursor-pointer font-medium text-gray-600">
                                  Details
                                </summary>
                                <pre className="mt-1 p-2 bg-white rounded text-gray-600 overflow-x-auto">
                                  {formatAuditDetails(log.details)}
                                </pre>
                              </details>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="text-center py-8">
                    <div className="text-gray-400 mb-4">
                      <svg className="mx-auto h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z" />
                      </svg>
                    </div>
                    <h3 className="text-lg font-medium text-gray-900 mb-2">No audit logs found</h3>
                    <p className="text-gray-500">No audit logs match your current filters.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Request Access Modal */}
      {showRequestModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex items-center justify-center p-4 z-50">
          <div className="relative bg-white rounded-lg shadow-xl max-w-md w-full mx-auto">
            <div className="p-4 sm:p-6">
              <h3 className="text-lg font-semibold mb-4">Request Access</h3>
              <form onSubmit={handleCreateRequest}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Resource
                    </label>
                    <select
                      required
                      value={newRequest.resource_id}
                      onChange={(e) => setNewRequest({...newRequest, resource_id: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                    >
                      <option value="">Select a resource</option>
                      {resources.map(resource => (
                        <option key={resource.id} value={resource.id}>
                          {resource.name} ({resource.hostname})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Reason for Access
                    </label>
                    <textarea
                      value={newRequest.reason}
                      onChange={(e) => setNewRequest({...newRequest, reason: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                      rows={3}
                      placeholder="Explain why you need access..."
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Access Until
                    </label>
                    <input
                      type="datetime-local"
                      required
                      value={newRequest.expires_at}
                      onChange={(e) => setNewRequest({...newRequest, expires_at: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                      min={new Date().toISOString().slice(0, 16)}
                      max={new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 16)}
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Maximum access duration is 24 hours
                    </p>
                  </div>
                </div>
                <div className="mt-6 flex flex-col sm:flex-row justify-end space-y-2 sm:space-y-0 sm:space-x-3">
                  <button
                    type="button"
                    onClick={() => setShowRequestModal(false)}
                    className="w-full sm:w-auto px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full sm:w-auto px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50"
                  >
                    {submitting ? 'Submitting...' : 'Submit Request'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Credential Management Modal */}
      {showCredentialModal && selectedResourceForCredential && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex items-center justify-center p-4 z-50">
          <div className="relative bg-white rounded-lg shadow-xl max-w-md w-full mx-auto">
            <div className="p-6">
              <h3 className="text-lg font-semibold mb-4">
                Manage Credentials - {selectedResourceForCredential.name}
              </h3>
              
              {/* Existing Credentials */}
              <div className="mb-4">
                <h4 className="font-medium mb-2">Existing Credentials</h4>
                {credentials.length > 0 ? (
                  <div className="space-y-2">
                    {credentials.map(cred => (
                      <div key={cred.id} className="flex justify-between items-center p-2 bg-gray-50 rounded">
                        <div>
                          <span className="font-medium">{cred.name}</span>
                          <span className="text-sm text-gray-600 ml-2">({cred.type})</span>
                        </div>
                          <button
                          onClick={() => handleDeleteCredential(cred.id, selectedResourceForCredential.id)}
                          className="text-red-600 hover:text-red-800 text-sm"
                        >
                          Delete
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500 text-sm">No credentials configured</p>
                )}
              </div>

              {/* Add New Credential Form */}
              <form onSubmit={handleCreateCredential}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Credential Name *
                    </label>
                    <input
                      type="text"
                      required
                      value={newCredential.name}
                      onChange={(e) => setNewCredential({...newCredential, name: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., admin-user, root-access"
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Type *
                    </label>
                    <select
                      required
                      value={newCredential.type}
                      onChange={(e) => setNewCredential({...newCredential, type: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="password">Password</option>
                      <option value="ssh_key">SSH Key</option>
                    </select>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Username *
                    </label>
                    <input
                      type="text"
                      required
                      value={newCredential.username}
                      onChange={(e) => setNewCredential({...newCredential, username: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g., root, admin, webuser"
                    />
                  </div>
                  
                  {newCredential.type === 'password' ? (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Password *
                      </label>
                      <input
                        type="password"
                        required
                        value={newCredential.password}
                        onChange={(e) => setNewCredential({...newCredential, password: e.target.value})}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="SSH password"
                      />
                    </div>
                  ) : (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Private Key *
                      </label>
                      <textarea
                        required
                        value={newCredential.private_key}
                        onChange={(e) => setNewCredential({...newCredential, private_key: e.target.value})}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        rows={6}
                        placeholder="Paste SSH private key here..."
                      />
                    </div>
                  )}
                </div>
                
                <div className="mt-6 flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => setShowCredentialModal(false)}
                    className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50"
                  >
                    {submitting ? 'Creating...' : 'Create Credential'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Create Resource Modal */}
      {showCreateResourceModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex items-center justify-center p-4 z-50">
          <div className="relative bg-white rounded-lg shadow-xl max-w-md w-full mx-auto">
            <div className="p-6">
              <h3 className="text-lg font-semibold mb-4">Create New Resource</h3>
              <form onSubmit={handleCreateResource}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Name *
                    </label>
                    <input
                      type="text"
                      required
                      minLength={3}
                      maxLength={100}
                      value={newResource.name}
                      onChange={(e) => setNewResource({...newResource, name: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Resource name"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Type *
                    </label>
                    <select
                      required
                      value={newResource.type}
                      onChange={(e) => setNewResource({...newResource, type: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="ssh">SSH</option>
                      <option value="rdp">RDP</option>
                      <option value="db">Database</option>
                      <option value="api">API</option>
                      <option value="web">Web</option>
                      <option value="service">Service</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Hostname *
                    </label>
                    <input
                      type="text"
                      required
                      value={newResource.hostname}
                      onChange={(e) => setNewResource({...newResource, hostname: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="hostname or IP address"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Port
                    </label>
                    <input
                      type="number"
                      min="1"
                      max="65535"
                      value={newResource.port || ''}
                      onChange={(e) => setNewResource({...newResource, port: e.target.value ? parseInt(e.target.value) : undefined})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Optional port number"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Criticality
                    </label>
                    <select
                      value={newResource.criticality}
                      onChange={(e) => setNewResource({...newResource, criticality: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Description
                    </label>
                    <textarea
                      value={newResource.description}
                      onChange={(e) => setNewResource({...newResource, description: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      rows={3}
                      placeholder="Resource description..."
                    />
                  </div>
                </div>
                <div className="mt-6 flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => setShowCreateResourceModal(false)}
                    className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50"
                  >
                    {submitting ? 'Creating...' : 'Create Resource'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Edit Resource Modal */}
      {showEditResourceModal && selectedResource && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex items-center justify-center p-4 z-50">
          <div className="relative bg-white rounded-lg shadow-xl max-w-md w-full mx-auto">
            <div className="p-6">
              <h3 className="text-lg font-semibold mb-4">Edit Resource</h3>
              <form onSubmit={handleUpdateResource}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Name *
                    </label>
                    <input
                      type="text"
                      required
                      minLength={3}
                      maxLength={100}
                      value={editResource.name || ''}
                      onChange={(e) => setEditResource({...editResource, name: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Type *
                    </label>
                    <select
                      required
                      value={editResource.type || ''}
                      onChange={(e) => setEditResource({...editResource, type: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="ssh">SSH</option>
                      <option value="rdp">RDP</option>
                      <option value="db">Database</option>
                      <option value="api">API</option>
                      <option value="web">Web</option>
                      <option value="service">Service</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Hostname *
                    </label>
                    <input
                      type="text"
                      required
                      value={editResource.hostname || ''}
                      onChange={(e) => setEditResource({...editResource, hostname: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Port
                    </label>
                    <input
                      type="number"
                      min="1"
                      max="65535"
                      value={editResource.port || ''}
                      onChange={(e) => setEditResource({...editResource, port: e.target.value ? parseInt(e.target.value) : undefined})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Criticality
                    </label>
                    <select
                      value={editResource.criticality || ''}
                      onChange={(e) => setEditResource({...editResource, criticality: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Description
                    </label>
                    <textarea
                      value={editResource.description || ''}
                      onChange={(e) => setEditResource({...editResource, description: e.target.value})}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      rows={3}
                    />
                  </div>
                </div>
                <div className="mt-6 flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => setShowEditResourceModal(false)}
                    className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50"
                  >
                    {submitting ? 'Updating...' : 'Update Resource'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Delete Resource Modal */}
      {showDeleteResourceModal && selectedResource && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex items-center justify-center p-4 z-50">
          <div className="relative bg-white rounded-lg shadow-xl max-w-md w-full mx-auto">
            <div className="p-6">
              <h3 className="text-lg font-semibold mb-4 text-red-600">Delete Resource</h3>
              
              {deleteDependencies ? (
                <div className="mb-4 p-4 bg-yellow-50 border border-yellow-200 rounded-md">
                  <p className="text-yellow-800 font-semibold mb-2">Resource has dependencies:</p>
                  <ul className="text-yellow-700 text-sm list-disc list-inside">
                    {deleteDependencies.active_access_requests > 0 && (
                      <li>Active Access Requests: {deleteDependencies.active_access_requests}</li>
                    )}
                    {deleteDependencies.credentials > 0 && (
                      <li>Credentials: {deleteDependencies.credentials}</li>
                    )}
                  </ul>
                  <div className="mt-3 flex items-center">
                    <input
                      type="checkbox"
                      id="forceDelete"
                      checked={deleteForce}
                      onChange={(e) => setDeleteForce(e.target.checked)}
                      className="mr-2"
                    />
                    <label htmlFor="forceDelete" className="text-yellow-800 text-sm">
                      Force delete (this will remove all dependencies)
                    </label>
                  </div>
                </div>
              ) : (
                <p className="mb-4 text-gray-700">
                  Are you sure you want to delete the resource <strong>"{selectedResource.name}"</strong>? 
                  This action cannot be undone.
                </p>
              )}

              <div className="flex justify-end space-x-3">
                <button
                  onClick={() => setShowDeleteResourceModal(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeleteResource}
                  disabled={submitting || (deleteDependencies && !deleteForce)}
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-md hover:bg-red-700 disabled:opacity-50"
                >
                  {submitting ? 'Deleting...' : 'Delete Resource'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Check History Modal */}
      {showCheckHistoryModal && selectedResourceForHistory && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex items-center justify-center p-4 z-50">
          <div className="relative bg-white rounded-lg shadow-xl max-w-4xl w-full mx-auto">
            <div className="p-6">
              <h3 className="text-lg font-semibold mb-4">
                Health Check History - {selectedResourceForHistory.name}
              </h3>
              
              <div className="mb-4">
                <p className="text-sm text-gray-600">
                  Hostname: {selectedResourceForHistory.hostname}:{selectedResourceForHistory.port || 'default'}
                </p>
              </div>

              <div className="max-h-96 overflow-y-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                        Checked At
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                        Status
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                        Response Time
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                        Error
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {resourceCheckHistory.map((check) => (
                      <tr key={check.id} className="hover:bg-gray-50">
                        <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-500">
                          {new Date(check.checked_at).toLocaleString()}
                        </td>
                        <td className="px-4 py-2 whitespace-nowrap">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium whitespace-nowrap flex items-center ${
                            check.is_online ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                          }`}>
                            <div className={`w-2 h-2 rounded-full mr-1 ${check.is_online ? 'bg-green-500' : 'bg-red-500'}`}></div>
                            {check.is_online ? 'Online' : 'Offline'}
                          </span>
                        </td>
                        <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-500">
                          {check.response_time ? `${check.response_time}ms` : '-'}
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-500 max-w-xs truncate">
                          {check.error_message || '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                
                {resourceCheckHistory.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    No health check history available
                  </div>
                )}
              </div>

              <div className="mt-6 flex justify-end">
                <button
                  onClick={() => {
                    setShowCheckHistoryModal(false);
                    setSelectedResourceForHistory(null);
                    setResourceCheckHistory([]);
                  }}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}