import { JwtPayload } from 'jsonwebtoken';
import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

// Initialize Supabase client
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
const supabase = createClient(supabaseUrl, supabaseKey);

// Ensure the JWT secret is defined
const JWT_SECRET = process.env.TOKEN_SECRET;
if (!JWT_SECRET) {
    throw new Error('JWT secret is not defined in the environment variables');
}

// PUT route (Update an existing user in the DB using JWT)
export async function PUT(request: NextRequest) {
    try {
        // Retrieve token from cookies
        const tokenCookie = request.cookies.get('token');
        if (!tokenCookie) {
            console.error('Token cookie is missing');
            return NextResponse.json({ error: 'Authorization token is missing or invalid.' }, { status: 401 });
        }

        // Extract the token value
        const token = tokenCookie.value;
        console.log('Token:', token);

        // Verify and decode the JWT
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET as string);
            console.log('Decoded JWT:', decoded);
        } catch (error) {
            if (error instanceof Error) {
                console.error('JWT verification failed:', error.message);
                return NextResponse.json({ error: 'Invalid or expired token.' }, { status: 401 });
            }
            console.error('Unknown error during JWT verification');
            return NextResponse.json({ error: 'An unknown error occurred during token verification.' }, { status: 500 });
        }

        // Type checking: Ensure `decoded` is an object and has the `email` property
        if (typeof decoded === 'object' && 'email' in decoded) {
            const { email } = decoded as JwtPayload;

            // 1- Find the user by the email from the JWT in Supabase
            const { data: user, error: userError } = await supabase
                .from('users')  // Assuming your table is named 'users'
                .select('*')
                .eq('email', email)
                .single();  // Get a single user

            if (userError || !user) {
                console.error('User not found for email:', email);
                return NextResponse.json({ error: 'User not found' }, { status: 404 });
            }

            // 2- Grab data from the request body
            const reqBody = await request.json();
            const { nom, prenom, datenaissance, telephone, adresse, password } = reqBody;

            // 3- Update user fields if provided
            const updates: any = {
                nom: nom || user.nom,
                prenom: prenom || user.prenom,
                datenaissance: datenaissance || user.datenaissance,
                telephone: telephone || user.telephone,
                adresse: adresse || user.adresse,
            };

            // 4- If a new password is provided, hash it before updating
            if (password) {
                const salt = await bcryptjs.genSalt(10);
                const hashedPassword = await bcryptjs.hash(password, salt);
                updates.password = hashedPassword;
            }

            // 5- Update the user in Supabase
            const { data: updatedUser, error: updateError } = await supabase
                .from('users')
                .update(updates)
                .eq('email', email)
                .single();

            if (updateError) {
                console.error('Error updating user:', updateError.message);
                return NextResponse.json({ error: 'Failed to update user' }, { status: 500 });
            }

            return NextResponse.json({
                message: 'User updated successfully!',
                success: true,
                updatedUser,
            });
        } else {
            console.error('Token does not contain an email');
            return NextResponse.json({ error: 'Token does not contain an email' }, { status: 400 });
        }
    } catch (error) {
        if (error instanceof Error) {
            console.error('Error during user update:', error.message);
            return NextResponse.json({ error: error.message }, { status: 500 });
        }
        console.error('Unknown error during user update');
        return NextResponse.json({ error: 'An unknown error occurred during user update.' }, { status: 500 });
    }
}
