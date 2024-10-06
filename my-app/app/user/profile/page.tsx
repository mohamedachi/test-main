'use client';

import Link from 'next/link';
import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import axios from 'axios';
import { FaAngleLeft } from 'react-icons/fa6';

// Haversine formula to calculate distance between two geographical points
function haversineDistance(lat1: number, lon1: number, lat2: number, lon2: number) {
	const toRad = (value: number) => (value * Math.PI) / 180;
	const R = 6371; // Radius of Earth in kilometers
	const dLat = toRad(lat2 - lat1);
	const dLon = toRad(lon2 - lon1);

	const a =
		Math.sin(dLat / 2) * Math.sin(dLat / 2) +
		Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
	const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
	return R * c; // Distance in kilometers
}

// Validate if an address is within 50 km of Paris
async function validateAddress(adresse: string) {
	const parisLat = 48.8566;
	const parisLon = 2.3522;

	try {
		const response = await axios.get(`https://api-adresse.data.gouv.fr/search/?q=${adresse}`);
		if (response.data.features.length === 0) {
			return { valid: false, message: 'Adresse non trouvée.' };
		}

		// Get latitude and longitude from the API response
		const [lon, lat] = response.data.features[0].geometry.coordinates;
		const distance = haversineDistance(lat, lon, parisLat, parisLon);

		if (distance <= 50) {
			return { valid: true, message: '' };
		} else {
			return { valid: false, message: 'L\'adresse doit être située à moins de 50 km de Paris.' };
		}
	} catch (error) {
		console.error('Error validating address:', error);
		return { valid: false, message: 'Erreur lors de la validation de l\'adresse.' };
	}
}

export default function profilePage() {
	const router = useRouter();

	const [user, setUser] = useState({
		nom: '',
		prenom: '',
		email: '',
		dateNaissance: '',  // Date will be handled as a string but should be in date format.
		telephone: '',  // Store the telephone as a string to accommodate leading zeros.
		adresse: '',
		password: '',
	});

	const [buttonDisabled, setButtonDisabled] = useState(true);
	const [loading, setLoading] = useState(false);
	const [addressError, setAddressError] = useState('');

  const logout = async () => {
    try {
      // Clear the token from cookies
      await axios.post('/user/api/users/logout'); // If you have a logout endpoint
      // Or clear cookies client-side
      document.cookie = 'token=; Max-Age=0; path=/;'; // Clear the token cookie

      // Redirect to login or home page
      router.push('/user/login');
    } catch (error: any) {
      console.log('Failed to log out', error.message);
    }
  }
	const update = async () => {
		try {
			setLoading(true);
			const { valid, message } = await validateAddress(user.adresse);
	
			if (!valid) {
				setAddressError(message);
				setLoading(false);
				return;
			}
	
			setAddressError(''); // Clear address error if valid
	
			// Corrected API endpoint with full payload
			const response = await axios.put('/user/api/users/profile', {
				nom: user.nom,
				prenom: user.prenom,
				email: user.email,
				datenaissance: user.dateNaissance,
				telephone: user.telephone,
				adresse: user.adresse,
			});
	
			console.log('update okay', response.data);
			
		} catch (error: any) {
			console.log('Failed to sign up the user', error.message);
		} finally {
			setLoading(false);
		}
	};
	
	
	useEffect(() => {
		// Check if all required fields are filled in
		if (
			user.nom.length > 0 &&
			user.prenom.length > 0 &&
			user.email.length > 0 &&
			user.dateNaissance.length > 0 &&
			user.telephone.length > 0 &&
			user.adresse.length > 0
		) {
			setButtonDisabled(false);
		} else {
			setButtonDisabled(true);
		}
	}, [user]);

	return (
		<div className="flex flex-col items-center justify-center min-h-screen py-2">
			<h1 className="py-10 mb-10 text-5xl">
				{loading ? 'Processing...' : 'Profile'}
				<span className="italic text-sm absolute top-50 ml-4 text-blue-600">
Welcome superiamo				</span>
			</h1>

			{/* Input Fields */}
			<input
				className="w-[350px] text-slate-800 p-2 border border-gray-300 rounded-lg mb-4 focus:outline-none focus:border-gray-600"
				id="nom"
				type="text"
				value={user.nom}
				onChange={(e) => setUser({ ...user, nom: e.target.value })}
				placeholder="Votre Nom..."
			/>

			<input
				className="w-[350px] text-slate-800 p-2 border border-gray-300 rounded-lg mb-4 focus:outline-none focus:border-gray-600"
				id="prenom"
				type="text"
				value={user.prenom}
				onChange={(e) => setUser({ ...user, prenom: e.target.value })}
				placeholder="Votre Prénom..."
			/>

			<input
				className="w-[350px] text-slate-800 p-2 border border-gray-300 rounded-lg mb-4 focus:outline-none focus:border-gray-600"
				id="email"
				type="email"
				value={user.email}
				onChange={(e) => setUser({ ...user, email: e.target.value })}
				placeholder="Votre Email..."
			/>

			<input
				className="w-[350px] text-slate-800 p-2 border border-gray-300 rounded-lg mb-4 focus:outline-none focus:border-gray-600"
				id="password"
				type="password"
				value={user.password}
				onChange={(e) => setUser({ ...user, password: e.target.value })}
				placeholder="Votre Mot de Passe..."
			/>

			{/* Date input for dateNaissance */}
			<input
				className="w-[350px] text-slate-800 p-2 border border-gray-300 rounded-lg mb-4 focus:outline-none focus:border-gray-600"
				id="dateNaissance"
				type="date"
				value={user.dateNaissance}
				onChange={(e) => setUser({ ...user, dateNaissance: e.target.value })}
				placeholder="Date de Naissance"
			/>

			{/* Number input for telephone */}
			<input
				className="w-[350px] text-slate-800 p-2 border border-gray-300 rounded-lg mb-4 focus:outline-none focus:border-gray-600"
				id="telephone"
				type="tel"
				value={user.telephone}
				onChange={(e) => setUser({ ...user, telephone: e.target.value.replace(/\D/g, '') })}
				placeholder="Votre Numéro de Téléphone..."
			/>

			{/* Address Input Field */}
			<input
				className="w-[350px] text-slate-800 p-2 border border-gray-300 rounded-lg mb-4 focus:outline-none focus:border-gray-600"
				id="adresse"
				type="text"
				value={user.adresse}
				onChange={(e) => setUser({ ...user, adresse: e.target.value })}
				placeholder="Votre Adresse..."
			/>

			{/* Error Message for Address Validation */}
			{addressError && <p className="text-red-500">{addressError}</p>}

			{/* Submit Button */}
			<button
				onClick={update}
				className="p-2 border border-gray-300 rounded-lg focus:outline-none focus:border-gray-600 uppercase px-40 py-3 mt-10 font-bold"
				disabled={buttonDisabled}>
				{loading ? 'updating ...' : 'change information'}
			</button>
      <button
        onClick={logout}
        className="p-2 border border-gray-300 rounded-lg focus:outline-none focus:border-gray-600 uppercase px-40 py-3 mt-10 font-bold">
        Logout
      </button>

			
		</div>
	);
}
