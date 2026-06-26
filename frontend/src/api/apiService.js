import axios from 'axios';

// Create an axios instance with default configuration
const apiService = axios.create({
  baseURL: 'http://localhost:5000/api', // Absolute backend URL as requested
  withCredentials: true, // Important for sending/receiving cookies across origins
  headers: {
    'Content-Type': 'application/json',
  },
});

export default apiService;
