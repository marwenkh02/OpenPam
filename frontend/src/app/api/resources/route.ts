import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8000';

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const token = request.headers.get('authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return NextResponse.json(
        { error: 'Authorization token required' },
        { status: 401 }
      );
    }

    // Build query parameters from search params
    const queryParams = new URLSearchParams();
    
    const q = searchParams.get('q');
    const type = searchParams.get('type');
    const criticality = searchParams.get('criticality');
    const page = searchParams.get('page') || '1';
    const limit = searchParams.get('limit') || '25';
    const sort_by = searchParams.get('sort_by') || 'name';
    const order = searchParams.get('order') || 'asc';

    if (q) queryParams.append('q', q);
    if (type) queryParams.append('type', type);
    if (criticality) queryParams.append('criticality', criticality);
    queryParams.append('page', page);
    queryParams.append('limit', limit);
    queryParams.append('sort_by', sort_by);
    queryParams.append('order', order);

    const queryString = queryParams.toString();
    const endpoint = queryString ? `/api/resources?${queryString}` : '/api/resources';

    const response = await fetch(`${BACKEND_URL}${endpoint}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      cache: 'no-store'
    });

    const data = await response.json();
    
    if (!response.ok) {
      return NextResponse.json(
        { error: data.detail || 'Failed to fetch resources' },
        { status: response.status }
      );
    }
    
    return NextResponse.json(data);
  } catch (error: any) {
    console.error('Resources API error:', error);
    return NextResponse.json(
      { error: error.message || 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const token = request.headers.get('authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return NextResponse.json(
        { error: 'Authorization token required' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { action, resourceId, force, ...resourceData } = body;

    let endpoint = '';
    let method = 'POST';

    if (action === 'create') {
      endpoint = '/api/resources';
    } else if (action === 'update') {
      endpoint = `/api/resources/${resourceId}`;
      method = 'PUT';
    } else if (action === 'delete') {
      endpoint = `/api/resources/${resourceId}`;
      method = 'DELETE';
    } else if (action === 'check') {
      endpoint = `/api/resources/${resourceId}/check`;
      method = 'POST';
    } else if (action === 'check-all') {
      endpoint = '/api/resources/check-all';
      method = 'POST';
    } else if (action === 'check-history') {
      endpoint = `/api/resources/${resourceId}/check-history`;
      method = 'GET';
    } else {
      return NextResponse.json(
        { error: 'Invalid action' },
        { status: 400 }
      );
    }

    // Add force parameter for delete if provided
    if (action === 'delete' && force !== undefined) {
      endpoint += `?force=${force}`;
    }

    const response = await fetch(`${BACKEND_URL}${endpoint}`, {
      method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: method !== 'GET' && method !== 'DELETE' ? JSON.stringify(resourceData) : undefined,
    });

    const data = await response.json();
    
    if (!response.ok) {
      return NextResponse.json(
        { 
          error: data.detail?.message || data.detail || 'Request failed',
          details: data.detail?.dependencies || null,
          force_required: data.detail?.force_required || false
        },
        { status: response.status }
      );
    }
    
    return NextResponse.json(data);
  } catch (error: any) {
    console.error('Resources API error:', error);
    return NextResponse.json(
      { error: error.message || 'Internal server error' },
      { status: 500 }
    );
  }
}