const fs = require('fs');
const path = require('path');

const CHALLENGES_DIR = path.join(__dirname, 'challenges');

function loadChallenges() {
    console.log('Loading challenges from:', CHALLENGES_DIR);
    const challenges = [];
    const categories = ['beginner', 'intermediate', 'advanced'];

    for (const category of categories) {
        const categoryPath = path.join(CHALLENGES_DIR, category);
        console.log('Checking category:', categoryPath);
        
        try {
            const files = fs.readdirSync(categoryPath);
            console.log('Found files:', files);

            for (const file of files) {
                if (file.endsWith('.json')) {
                    const filePath = path.join(categoryPath, file);
                    console.log('Loading file:', filePath);
                    const challengeData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                    challenges.push({
                        ...challengeData,
                        solved: []
                    });
                }
            }
        } catch (error) {
            console.error('Error loading category:', category, error);
        }
    }

    console.log('Loaded total challenges:', challenges.length);
    return challenges;
}

module.exports = {
    loadChallenges
}; 