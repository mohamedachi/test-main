import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    nom: {
        type: String,
        required: [false, "Nom is required"],
    },
    prenom: {
        type: String,
        required: [false, "Prenom is required"],
    },
    email: {
        type: String,
        required: [false, "Email is required"],
        unique: false,
        match: [/\S+@\S+\.\S+/, "Please enter a valid email"],
    },
    datenaissance: {
        type: Date, // Changed to Date for better consistency
        required: [false, "Date of birth is required"],
    },
    telephone: {
        type: String,
        required: [false, "Telephone is required"],
        unique: false,
    },
    adresse: {
        type: String,
        required: [false, "Adresse is required"],
    },
    password: {
        type: String,
        required: [false, "Password is required"],
    },
}, { timestamps: false }); // Adding timestamps to track creation and updates

const User = mongoose.models.User || mongoose.model('User', userSchema);
export default User;
