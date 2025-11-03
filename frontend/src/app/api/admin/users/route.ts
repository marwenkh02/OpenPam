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
    const isActive = searchParams.get('is_active');
    const isAdmin = searchParams.get('is_admin');
    const limit = searchParams.get('limit') || '50';
    const offset = searchParams.get('offset') || '0';

    if (q) queryParams.append('q', q);
    if (isActive !== null) queryParams.append('is_active', isActive);
    if (isAdmin !== null) queryParams.append('is_admin', isAdmin);
    queryParams.append('limit', limit);
    queryParams.append('offset', offset);

    const queryString = queryParams.toString();
    const endpoint = queryString ? `/api/admin/users?${queryString}` : '/api/admin/users';

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
        { error: data.detail || 'Failed to fetch users' },
        { status: response.status }
      );
    }
    
    return NextResponse.json(data);
  } catch (error: any) {
    console.error('Users API error:', error);
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

    const body = await request.json();
    
    if (action === 'update-role') {
      const { userId, isAdmin } = body;
      const response = await fetch(`${BACKEND_URL}/api/admin/users/${userId}/role`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ is_admin: isAdmin }),
      });

      const data = await response.json();
      
      if (!response.ok) {
        return NextResponse.json(
          { error: data.detail || 'Failed to update user role' },
          { status: response.status }
        );
      }
      
      return NextResponse.json(data);
    }
    
    if (action === 'update-status') {
      const { userId, isActive } = body;
      const response = await fetch(`${BACKEND_URL}/api/admin/users/${userId}/status`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ is_active: isActive }),
      });

      const data = await response.json();
      
      if (!response.ok) {
        return NextResponse.json(
          { error: data.detail || 'Failed to update user status' },
          { status: response.status }
        );
      }
      
      return NextResponse.json(data);
    }
    
    if (action === 'reset-password') {
      const { userId, newPassword } = body;
      
      // Validate password on frontend first
      const errors = [];
      if (newPassword.length < 12) {
        errors.push("Password must be at least 12 characters long");
      }
      if (!anyUpperCase(newPassword)) {
        errors.push("Password must contain at least one uppercase letter");
      }
      if (!anyLowerCase(newPassword)) {
        errors.push("Password must contain at least one lowercase letter");
      }
      if (!anyDigit(newPassword)) {
        errors.push("Password must contain at least one digit");
      }
      if (!anySpecialChar(newPassword)) {
        errors.push("Password must contain at least one special character");
      }
      
      if (errors.length > 0) {
        return NextResponse.json(
          { error: errors.join('; ') },
          { status: 422 }
        );
      }

      const response = await fetch(`${BACKEND_URL}/api/admin/users/${userId}/reset-password`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ new_password: newPassword }),
      });

      const data = await response.json();
      
      if (!response.ok) {
        // Handle backend validation errors
        if (data.detail && typeof data.detail === 'object' && data.detail.errors) {
          return NextResponse.json(
            { error: data.detail.errors.join('; ') },
            { status: response.status }
          );
        }
        return NextResponse.json(
          { error: data.detail || 'Failed to reset password' },
          { status: response.status }
        );
      }
      
      return NextResponse.json(data);
    }
    
    if (action === 'delete') {
      const { userId } = body;
      const response = await fetch(`${BACKEND_URL}/api/admin/users/${userId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();
      
      if (!response.ok) {
        // Handle dependency errors
        if (data.detail && typeof data.detail === 'object') {
          return NextResponse.json(
            { 
              error: data.detail.message || 'Failed to delete user',
              dependencies: data.detail.dependencies 
            },
            { status: response.status }
          );
        }
        return NextResponse.json(
          { error: data.detail || 'Failed to delete user' },
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
    console.error('Users API error:', error);
    return NextResponse.json(
      { error: error.message || 'Internal server error' },
      { status: 500 }
    );
  }
}

// Helper functions for password validation
function anyUpperCase(str: string): boolean {
  return /[A-Z]/.test(str);
}

function anyLowerCase(str: string): boolean {
  return /[a-z]/.test(str);
}

function anyDigit(str: string): boolean {
  return /\d/.test(str);
}

function anySpecialChar(str: string): boolean {
  return /[!@#$%^&*(),.?:{}|<>]/.test(str);
}