import { NextRequest, NextResponse } from 'next/server';

import bcryptjs from 'bcryptjs';
import { supabase } from '@/utils/supabase/supabaseclient';

// POST route (Create a new user inside Supabase)
export async function POST(request: NextRequest) {
	try {
		// grab data from body
		const reqBody = await request.json();

		// destructure the incoming variables
		const { nom, prenom, email, datenaissance, telephone, adresse, password } = reqBody;

		// REMOVE IN PRODUCTION
		console.log(reqBody);

		// Check if user already exists
		const { data: existingUser, error: userFetchError } = await supabase
			.from('users')
			.select('*')
			.eq('email', email)
			.single();

		if (existingUser) {
			return NextResponse.json(
				{
					error: 'This user already exists',
				},
				{ status: 400 }
			);
		}

		// Hash password
		const salt = await bcryptjs.genSalt(10);
		const hashedPassword = await bcryptjs.hash(password, salt);

		// Create a new user in Supabase
		const { data: newUser, error: insertError } = await supabase
			.from('users')
			.insert([
				{
					nom,
					prenom,
					email,
					datenaissance,
					telephone,
					adresse,
					password: hashedPassword,
				},
			])
			.single();

		if (insertError) {
			throw new Error(insertError.message);
		}

		return NextResponse.json({
			message: 'User created!',
			success: true,
			newUser,
		});
	} catch (error: any) {
		return NextResponse.json({ error: error.message }, { status: 500 });
	}
}
