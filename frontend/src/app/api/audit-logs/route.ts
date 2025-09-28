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
    
    const userId = searchParams.get('user_id');
    const actionType = searchParams.get('action_type');
    const severity = searchParams.get('severity');
    const resourceId = searchParams.get('resource_id');
    const startDate = searchParams.get('start_date');
    const endDate = searchParams.get('end_date');
    const limit = searchParams.get('limit') || '100';
    const offset = searchParams.get('offset') || '0';

    if (userId) queryParams.append('user_id', userId);
    if (actionType) queryParams.append('action_type', actionType);
    if (severity) queryParams.append('severity', severity);
    if (resourceId) queryParams.append('resource_id', resourceId);
    if (startDate) queryParams.append('start_date', startDate);
    if (endDate) queryParams.append('end_date', endDate);
    queryParams.append('limit', limit);
    queryParams.append('offset', offset);

    const queryString = queryParams.toString();
    const endpoint = queryString ? `/audit-logs/?${queryString}` : '/audit-logs/';

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
        { error: data.detail || 'Failed to fetch audit logs' },
        { status: response.status }
      );
    }
    
    return NextResponse.json(data);
  } catch (error: any) {
    console.error('Audit logs API error:', error);
    return NextResponse.json(
      { error: error.message || 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const action = searchParams.get('action');
    const token = request.headers.get('authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return NextResponse.json(
        { error: 'Authorization token required' },
        { status: 401 }
      );
    }

    if (action === 'stats') {
      const response = await fetch(`${BACKEND_URL}/audit-logs/stats`, {
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
          { error: data.detail || 'Failed to fetch audit stats' },
          { status: response.status }
        );
      }
      
      return NextResponse.json(data);
    }

    return NextResponse.json(
      { error: 'Invalid action' },
      { status: 400 }
    );
  } catch (error: any) {
    console.error('Audit logs API error:', error);
    return NextResponse.json(
      { error: error.message || 'Internal server error' },
      { status: 500 }
    );
  }
}