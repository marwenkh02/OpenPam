import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8000';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, ...data } = body;
    
    let endpoint = '';
    let method = 'POST';
    
    if (action === 'login') {
      endpoint = '/token';
    } else if (action === 'signup') {
      endpoint = '/users/';
    } else if (action === 'getUser') {
      endpoint = '/users/me/';
      method = 'GET';
    } else {
      return NextResponse.json(
        { error: 'Invalid action' },
        { status: 400 }
      );
    }

    // Prepare headers
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };

    // Add authorization header if token is provided
    if (data.token) {
      headers['Authorization'] = `Bearer ${data.token}`;
    }

    // Prepare request options
    const requestOptions: RequestInit = {
      method,
      headers,
      cache: 'no-store'
    };

    // Add body for non-GET requests
    if (method !== 'GET') {
      requestOptions.body = JSON.stringify(data);
    }

    const response = await fetch(`${BACKEND_URL}${endpoint}`, requestOptions);
    
    // Handle different response types
    const contentType = response.headers.get('content-type');
    let responseData;
    
    if (contentType && contentType.includes('application/json')) {
      responseData = await response.json();
    } else {
      const text = await response.text();
      console.error('Non-JSON response from backend:', text);
      throw new Error(`Backend returned unexpected format: ${text.substring(0, 100)}`);
    }
    
    if (!response.ok) {
      // Pass through backend validation errors
      return NextResponse.json(
        { 
          error: responseData.detail || responseData.error || 'Request failed',
          detail: responseData.detail // Include full detail for validation errors
        },
        { status: response.status }
      );
    }
    
    return NextResponse.json(responseData);
  } catch (error: any) {
    console.error('API route error:', error);
    
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return NextResponse.json(
        { error: 'Cannot connect to backend server. Please make sure it is running on port 8000.' },
        { status: 503 }
      );
    }
    
    return NextResponse.json(
      { error: error.message || 'Internal server error' },
      { status: 500 }
    );
  }
}