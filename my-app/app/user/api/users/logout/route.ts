import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
    try {
        // Create a response object
        const response = NextResponse.json({
            message: 'Logout successful',
            success: true,
        });

        // Clear the token cookie by setting it with an expired date
        response.cookies.set('token', '', {
            httpOnly: true,
            expires: new Date(0), // Set the cookie to expire immediately
            path: '/', // Ensure the path matches where the cookie was set
        });

        return response;
    } catch (error) {
        console.error('Error during logout:', error);
        return NextResponse.json({ error: 'An error occurred during logout.' }, { status: 500 });
    }
}