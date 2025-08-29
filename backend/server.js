// Temporary placeholder - Replace with actual content from artifact
const express = require('express');
const app = express();
const PORT = 3001;

app.get('/api/test', (req, res) => {
    res.json({ message: 'Backend server placeholder - Please replace with actual code' });
});

app.listen(PORT, () => {
    console.log(`Placeholder server running on port ${PORT}`);
    console.log('⚠️  Please replace this file with the actual server.js content from the artifact');
});
