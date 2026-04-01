import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const githubScoringService = {
    getRepoScore: async (username, repoName) => {
        try {
            const response = await axios.get(`${API_URL}/api/github/score/${username}/${repoName}`, {
                withCredentials: true
            });
            return response.data;
        } catch (error) {
            console.error('Error fetching GitHub score:', error);
            throw error;
        }
    },
    getAccountScores: async (username) => {
        try {
            const response = await axios.get(`${API_URL}/api/github/account/${username}`, {
                withCredentials: true
            });
            return response.data;
        } catch (error) {
            console.error('Error fetching GitHub account scores:', error);
            throw error;
        }
    },
    connectGithub: async (connectionData) => {
        try {
            const response = await axios.post(`${API_URL}/api/github/connect`, connectionData, {
                withCredentials: true
            });
            return response.data;
        } catch (error) {
            console.error('Error connecting GitHub:', error);
            throw error;
        }
    }
};

export default githubScoringService;
