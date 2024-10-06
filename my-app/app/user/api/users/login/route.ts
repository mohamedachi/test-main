import dance from '@/models/userModel';
import { NextRequest, NextResponse } from 'next/server';
import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { connectToMongoDB } from '@/dbConfig/dbconfig';

connectToMongoDB();

export async function POST(request: NextRequest) {
    try {
        // 1- Grab the data inside the request
        const reqBody = await request.json();
        const { email, password } = reqBody;
        console.log('Request Body:', reqBody);

        // 2- Check if this user exists by checking its email before login
        const user = await dance.findOne({ email });
        if (!user) {
            return NextResponse.json({ error: 'User  does not exist in DB' }, { status: 400 });
        }
        console.log('User  found:', user);

        // 3- Check if the password is correct
        const validPassword = await bcryptjs.compare(password, user.password);
        if (!validPassword) {
            return NextResponse.json({ error: 'Invalid password' }, { status: 400 });
        }

        // 4- Create the TOKEN data
        const tokenData = {
            id: user._id,
            email: user.email,
            nom: user.nom,
            prenom: user.prenom,
            datenaissance: user.datenaissance,
            telephone: user.telephone,
            adresse: user.adresse,
        };

        // 4.1 - Create TOKEN
        const token = jwt.sign(tokenData, process.env.TOKEN_SECRET!, { expiresIn: '2d' });

        // 4.2- Send TOKEN to user's cookies
        const response = NextResponse.json({
            message: 'Login Successful',
            success: true,
        });

        // Set the token in a cookie
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