import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';

// Initialize Supabase client
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
const supabase = createClient(supabaseUrl, supabaseKey);

export async function POST(request: NextRequest) {
    try {
        // 1- Grab the data from the request body
        const reqBody = await request.json();
        const { email, password } = reqBody;
        console.log('Request Body:', reqBody);

        // 2- Query Supabase Database to find the user by email
        const { data: user, error: userError } = await supabase
            .from('users')  // Assuming your table is named 'users'
            .select('*')
            .eq('email', email)
            .single();  // single() to get a single user

        if (userError || !user) {
            return NextResponse.json({ error: 'User does not exist in the database' }, { status: 400 });
        }

        console.log('User found:', user);

        // 3- Check if the password is correct using bcryptjs
        const validPassword = await bcryptjs.compare(password, user.password);
        if (!validPassword) {
            return NextResponse.json({ error: 'Invalid password' }, { status: 400 });
        }

        // 4- Create the TOKEN data
        const tokenData = {
            id: user.id,
            email: user.email,
            nom: user.nom,  // Adjust these fields based on your user table
            prenom: user.prenom,
            datenaissance: user.datenaissance,
            telephone: user.telephone,
            adresse: user.adresse,
        };

        // 5- Create the JWT Token
        const token = jwt.sign(tokenData, process.env.TOKEN_SECRET!, { expiresIn: '2d' });

        // 6- Send the token in a cookie
        const response = NextResponse.json({
            message: 'Login Successful',
            success: true,
        });

        response.cookies.set('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Only set secure flag in production
            sameSite: 'strict', // Adjust based on your needs
        });

        return response;
    } catch (error: any) {
        console.error('Error during login:', error);
        return NextResponse.json({ error: error.message }, { status: 500 });
    }
}
