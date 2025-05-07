// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');
const nodemailer = require('nodemailer');
const session = require('express-session');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const db = require('./db');
const { loadChallenges } = require('./challengeLoader');

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database
db.initDatabase()
    .then(() => {
        console.log('Database initialized');
        return Promise.all([
            db.createFirstAdmin(),
            db.initSystemSettings(),
            db.verifyGuestUser()
        ]);
    })
    .then(([adminCreated, _, guestCreated]) => {
        if (adminCreated) {
            console.log('First admin user created');
        }
        if (guestCreated) {
            console.log('Guest user created/updated');
        }
        console.log('System settings initialized');
    })
    .catch(err => {
        console.error('Database initialization error:', err);
    });

// Load challenges from files
const challenges = loadChallenges();

// In-memory database for user authentication
const users = [];

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Set layout
app.use(expressLayouts);
app.set('layout', 'layouts/main');

// Middleware for parsing form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set up session management
app.use(session({
  secret: process.env.SESSION_SECRET || 'vuwctf-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Set up flash messages
app.use(flash());

// Middleware to make flash messages available to all templates
app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.user = req.session.user || null;

  // Helper functions for the template
  res.locals.getBadgeColor = (category) => {
    switch (category) {
      case 'Web': return 'success';
      case 'Crypto': return 'danger';
      case 'OSINT': return 'info';
      case 'Stego': return 'warning';
      case 'Forensics': return 'secondary';
      case 'Reverse': return 'dark';
      case 'Binary': return 'danger';
      default: return 'primary';
    }
  };

  res.locals.getDifficultyColor = (difficulty) => {
    switch (difficulty) {
      case 'Beginner': return 'success';
      case 'Intermediate': return 'warning';
      case 'Advanced': return 'danger';
      default: return 'secondary';
    }
  };

  res.locals.getChallengeDescription = (id) => {
    switch (id) {
      case 1: return 'Sometimes the information you need is right in front of you, just not visible at first glance.';
      case 2: return 'Learn about Base64 encoding and how to decode it to find hidden messages.';
      case 3: return 'Open Source Intelligence involves gathering information from publicly available sources.';
      case 4: return 'Steganography is the practice of hiding messages within ordinary, non-secret data or files.';
      case 5: return 'SQL injection is a code injection technique used to attack data-driven applications.';
      case 6: return 'Digital forensics involves investigating and analyzing digital data to uncover hidden information.';
      case 7: return 'The Caesar cipher is one of the earliest known encryption techniques, named after Julius Caesar.';
      case 8: return 'Reverse engineering involves analyzing how a program works to understand its functionality.';
      case 9: return 'JSON Web Tokens (JWT) are commonly used for authentication and information exchange.';
      case 10: return 'Buffer overflow is a vulnerability that occurs when a program writes more data to a buffer than it can hold.';
      case 11: return 'RSA is a public-key cryptosystem widely used for secure data transmission.';
      case 12: return 'Memory forensics involves analyzing the volatile memory (RAM) of a computer system to find evidence.';
      default: return '';
    }
  };

  next();
});

// Helper function for challenge category badge colors
app.locals.getBadgeColor = function(category) {
    const colors = {
        'Web': 'primary',
        'Crypto': 'success',
        'OSINT': 'info',
        'Stego': 'warning',
        'Forensics': 'danger',
        'Reverse': 'secondary',
        'Binary': 'dark'
    };
    return colors[category] || 'secondary';
};

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  req.flash('error_msg', 'Please log in to access this page');
  res.redirect('/login');
};

// Admin middleware
const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    req.flash('error_msg', 'You do not have permission to access this page');
    res.redirect('/');
};

// Routes
app.get('/', (req, res) => {
  res.render('index', {
    title: 'Victoria University of Wellington CTF',
    activePage: 'home'
  });
});

app.get('/about', (req, res) => {
  res.render('about', {
    title: 'About Us | VUW CTF',
    activePage: 'about'
  });
});

app.get('/events', (req, res) => {
  res.render('events', {
    title: 'Events | VUW CTF',
    activePage: 'events'
  });
});

app.get('/resources', (req, res) => {
  res.render('resources', {
    title: 'Resources | VUW CTF',
    activePage: 'resources'
  });
});

// Challenges route - accessible to all, with additional features for logged-in users
app.get('/challenges', async (req, res) => {
  try {
    console.log('Starting to load challenges...');
    // Load challenges fresh each time
    const challenges = loadChallenges();
    console.log('Challenges loaded:', challenges);

    // Get query parameters
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 4;
    const categories = req.query.categories ? req.query.categories.split(',') : [];
    const sortBy = req.query.sortBy || 'points';
    const sortOrder = req.query.sortOrder || 'ASC';

    // Filter challenges by category if specified
    let filteredChallenges = challenges;
    if (categories.length > 0) {
      filteredChallenges = challenges.filter(challenge => 
        categories.includes(challenge.category)
      );
    }

    // Sort challenges
    filteredChallenges.sort((a, b) => {
      if (sortBy === 'points') {
        return sortOrder === 'ASC' ? a.points - b.points : b.points - a.points;
      }
      return 0;
    });

    // Calculate pagination
    const totalChallenges = filteredChallenges.length;
    const totalPages = Math.ceil(totalChallenges / perPage);
    const startIndex = (page - 1) * perPage;
    const endIndex = startIndex + perPage;
    const paginatedChallenges = filteredChallenges.slice(startIndex, endIndex);

    // Calculate category statistics
    const categoryStats = {};
    challenges.forEach(challenge => {
      const category = challenge.category || 'Uncategorized';
      if (!categoryStats[category]) {
        categoryStats[category] = 0;
      }
      categoryStats[category]++;
    });

    // Get available categories
    const availableCategories = [...new Set(challenges.map(c => c.category))];

    // Prepare data for logged-in users
    let userData = null;
    if (req.session.user) {
      const userId = req.session.user.id;
      const user = req.session.user;
      const solvedChallenges = user.solved || [];
      
      userData = {
        user,
        solvedCount: solvedChallenges.length,
        solvedChallenges: solvedChallenges
      };
    }

    // Prepare modal data
    const modalData = paginatedChallenges.map(challenge => ({
      id: challenge.id,
      name: challenge.name,
      description: challenge.description,
      challenge_description: challenge.challenge_description,
      hint: challenge.hint,
      resources: challenge.resources,
      hasFile: challenge.resources && challenge.resources.some(r => r.url.startsWith('/challenges/')),
      fileUrl: challenge.resources && challenge.resources.find(r => r.url.startsWith('/challenges/'))?.url,
      fileLabel: challenge.resources && challenge.resources.find(r => r.url.startsWith('/challenges/'))?.name,
      hasWebpage: challenge.resources && challenge.resources.some(r => r.url.endsWith('.html')),
      webpageUrl: challenge.resources && challenge.resources.find(r => r.url.endsWith('.html'))?.url
    }));

    console.log('Rendering challenges page with:', {
      totalChallenges,
      paginatedChallenges: paginatedChallenges.length,
      categories: availableCategories
    });

    res.render('challenges', {
      title: 'Practice Challenges | VUW CTF',
      activePage: 'challenges',
      challenges: paginatedChallenges,
      authenticated: !!req.session.user,
      totalChallenges,
      categoryStats,
      userData,
      modalData,
      pagination: {
        currentPage: page,
        totalPages,
        perPage
      },
      filters: {
        categories: availableCategories,
        selectedCategories: categories,
        sortBy,
        sortOrder
      }
    });
  } catch (error) {
    console.error('Error in /challenges route:', error);
    console.error('Error stack:', error.stack);
    req.flash('error_msg', 'An error occurred while loading challenges');
    res.redirect('/');
  }
});

// Flag submission route - only for authenticated users
app.post('/submit-flag', isAuthenticated, async (req, res) => {
  const { challengeId, flag } = req.body;
  const userId = req.session.user.id;

  try {
    const challenge = await db.getChallengeById(challengeId);

    if (!challenge) {
      return res.json({ success: false, message: 'Challenge not found' });
    }

    // Check if already solved
    const isSolved = await db.isChallengeSolved(userId, challengeId);
    if (isSolved) {
      return res.json({ success: false, message: 'You have already solved this challenge' });
    }

    if (challenge.flag === flag) {
      // Mark as solved and update points
      await db.solveChallenge(userId, challengeId);
      await db.updateUserPoints(userId, challenge.points);

      // Get updated user points
      const user = await db.getUserById(userId);

      return res.json({
        success: true,
        message: `Correct! You earned ${challenge.points} points!`,
        points: challenge.points,
        totalPoints: user.points
      });
    } else {
      return res.json({ success: false, message: 'Incorrect flag. Try again!' });
    }
  } catch (error) {
    console.error('Flag submission error:', error);
    return res.json({ success: false, message: 'An error occurred while submitting the flag' });
  }
});

// Scoreboard route
app.get('/scoreboard', isAuthenticated, async (req, res) => {
    try {
        const users = await db.getAllUsers();
        const challenges = await db.getChallenges();
        const totalChallenges = challenges.length;

        // Calculate main leaderboard
        const leaderboard = await Promise.all(users.map(async user => {
            const solvedChallenges = await db.getSolvedChallenges(user.id);
            const totalPoints = solvedChallenges.reduce((total, sc) => {
                const challenge = challenges.find(c => c.id === sc.id);
                return total + (challenge ? challenge.points : 0);
            }, 0);
            return {
                ...user,
                solved: solvedChallenges.length,
                points: totalPoints,
                completionRate: totalChallenges > 0 ? ((solvedChallenges.length / totalChallenges) * 100).toFixed(1) : 0
            };
        }));
        leaderboard.sort((a, b) => b.points - a.points);

        // Calculate category leaderboards
        const categoryLeaderboards = {};
        const categories = [...new Set(challenges.map(c => c.category))];

        for (const category of categories) {
            if (!category) continue;

            // Get challenges in this category
            const categoryChallenges = challenges.filter(c => c.category === category);
            const categoryTotal = categoryChallenges.length;

            // Calculate user stats for this category
            const categoryUsers = await Promise.all(users.map(async user => {
                const solvedChallenges = await db.getSolvedChallenges(user.id);
                const solvedInCategory = solvedChallenges.filter(sc => 
                    categoryChallenges.some(c => c.id === sc.id)
                );
                
                // Calculate points earned in this category
                const categoryPoints = solvedInCategory.reduce((total, sc) => {
                    const challenge = categoryChallenges.find(c => c.id === sc.id);
                    return total + (challenge ? challenge.points : 0);
                }, 0);

                return {
                    ...user,
                    solved: solvedInCategory.length,
                    total: categoryTotal,
                    points: categoryPoints,
                    completionRate: categoryTotal > 0 ? ((solvedInCategory.length / categoryTotal) * 100).toFixed(1) : 0
                };
            }));

            // Filter out users with no solved challenges in this category and sort by points
            categoryLeaderboards[category] = categoryUsers
                .filter(user => user.solved > 0)
                .sort((a, b) => b.points - a.points);
        }

        res.render('scoreboard', {
            title: 'Scoreboard | VUW CTF',
            activePage: 'scoreboard',
            currentUser: req.session.user,
            leaderboard,
            totalChallenges,
            categoryLeaderboards
        });
    } catch (error) {
        console.error('Error loading scoreboard:', error);
        req.flash('error_msg', 'Error loading scoreboard. Please try again later.');
        res.redirect('/');
    }
});

// Auth routes
app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/challenges');
  }
  res.render('login', {
    title: 'Login | VUW CTF',
    activePage: 'login',
    showGuestLogin: false
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await db.getUserByUsername(username);

    if (!user) {
      req.flash('error_msg', 'User not found');
      return res.redirect('/login');
    }

    if (await bcrypt.compare(password, user.password)) {
      // Update last login
      await db.updateUserLastLogin(user.id);

      // Create session
      req.session.user = {
        id: user.id,
        username: user.username,
        points: user.points || 0,
        isAdmin: user.isAdmin || false,
        isGuest: user.isGuest || false
      };
      req.flash('success_msg', 'You are now logged in');
      return res.redirect('/challenges');
    } else {
      req.flash('error_msg', 'Password incorrect');
      return res.redirect('/login');
    }
  } catch (error) {
    console.error('Login error:', error);
    req.flash('error_msg', 'An error occurred during login');
    return res.redirect('/login');
  }
});

app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/challenges');
  }
  res.render('register', {
    title: 'Register | VUW CTF',
    activePage: 'register'
  });
});

app.post('/register', async (req, res) => {
  const { username, email, password, password2 } = req.body;

  // Validation
  const errors = [];

  if (!username || !email || !password || !password2) {
    errors.push('Please fill in all fields');
  }

  if (password !== password2) {
    errors.push('Passwords do not match');
  }

  if (password.length < 6) {
    errors.push('Password should be at least 6 characters');
  }

  try {
    // Check if username exists
    const existingUser = await db.getUserByUsername(username);
    if (existingUser) {
      errors.push('Username already exists');
    }

    // Check if email exists (you'll need to add this function to db.js)
    const existingEmail = await db.getUserByEmail(email);
    if (existingEmail) {
      errors.push('Email already in use');
    }

    if (errors.length > 0) {
      return res.render('register', {
        title: 'Register | VUW CTF',
        activePage: 'register',
        errors,
        username,
        email
      });
    }

    // Create new user
    await db.createUser(username, email, password);

    req.flash('success_msg', 'You are now registered and can log in');
    res.redirect('/login');
  } catch (error) {
    console.error('Registration error:', error);
    req.flash('error_msg', 'An error occurred during registration');
    return res.redirect('/register');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/login');
  });
});

app.get('/contact', (req, res) => {
  res.render('contact', {
    title: 'Contact Us | VUW CTF',
    activePage: 'contact',
    message: null
  });
});

// Handle contact form submission
app.post('/contact', async (req, res) => {
  const { name, email, subject, message, newsletter } = req.body;

  // Check if we have an email password configured
  const emailPassword = process.env.EMAIL_PASSWORD;
  if (!emailPassword) {
    console.error('ERROR: No EMAIL_PASSWORD environment variable set.');
    console.error('To send emails, you need to set up an app password for Gmail:');
    console.error('1. Create an .env file in the project root');
    console.error('2. Add EMAIL_PASSWORD=your_gmail_app_password to the file');
    console.error('3. Restart the server');

    return res.render('contact', {
      title: 'Contact Us | VUW CTF',
      activePage: 'contact',
      message: {
        type: 'warning',
        text: 'Email configuration is incomplete. Please contact the administrator.'
      }
    });
  }

  try {
    // Create transporter with SMTP settings for Gmail
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'vuwctf@gmail.com',
        pass: emailPassword
      }
    });

    // Email content
    const mailOptions = {
      from: `"VUW CTF Contact Form" <vuwctf@gmail.com>`, // Must use the same email as auth
      replyTo: email, // Set the reply-to field to the user's email
      to: 'vuwctf@gmail.com',
      subject: `Contact Form: ${subject}`,
      text: `
        Name: ${name}
        Email: ${email}
        Subject: ${subject}
        Newsletter: ${newsletter ? 'Yes' : 'No'}
        
        Message:
        ${message}
      `,
      html: `
        <h3>New Contact Form Submission</h3>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Newsletter:</strong> ${newsletter ? 'Yes' : 'No'}</p>
        <p><strong>Message:</strong></p>
        <p>${message.replace(/\n/g, '<br>')}</p>
      `
    };

    // Log the email content and send it
    console.log('Sending email with:', { ...mailOptions, auth: '***REDACTED***' });

    // Actually send the email
    await transporter.sendMail(mailOptions);

    res.render('contact', {
      title: 'Contact Us | VUW CTF',
      activePage: 'contact',
      message: {
        type: 'success',
        text: 'Your message has been sent! We will get back to you soon.'
      }
    });
  } catch (error) {
    console.error('Error sending email:', error);

    // Provide more helpful error message
    let errorMessage = 'There was an error sending your message. Please try again later.';

    // Add specific guidance for common Gmail errors
    if (error.code === 'EAUTH') {
      errorMessage = 'Authentication failed. Please check that you are using an App Password for Gmail, not your regular password.';
      console.error('\nGmail App Password Guide:');
      console.error('1. Make sure 2-factor authentication is enabled on your Google account');
      console.error('2. Go to your Google Account > Security > App passwords');
      console.error('3. Generate a new app password for "Mail" and "Other (Custom name)"');
      console.error('4. Use that 16-character password in your .env file');
      console.error('5. If using a Google Workspace account, ensure API access is enabled by the admin');
    }

    res.render('contact', {
      title: 'Contact Us | VUW CTF',
      activePage: 'contact',
      message: {
        type: 'danger',
        text: errorMessage
      }
    });
  }
});

// Profile route
app.get('/profile', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const user = await db.getUserById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/');
        }

        // Calculate user rank
        const userRank = await db.getUserRank(userId);

        // Get total users count
        const totalUsers = await db.getTotalUsers();

        // Get solved challenges
        const solvedChallenges = await db.getSolvedChallenges(userId);

        // Calculate user streak
        const userStreak = await db.getUserStreak(userId);

        // Calculate category stats for the user
        const categoryStats = {};
        const allChallenges = await db.getChallenges();
        
        allChallenges.forEach(challenge => {
            const category = challenge.category || 'Uncategorized';
            if (!categoryStats[category]) {
                categoryStats[category] = { solved: 0, total: 0, points: 0 };
            }
            categoryStats[category].total++;

            if (solvedChallenges.some(sc => sc.id === challenge.id)) {
                categoryStats[category].solved++;
                categoryStats[category].points += challenge.points;
            }
        });

        // Get recently solved challenges
        const recentlySolved = solvedChallenges
            .sort((a, b) => new Date(b.solved_at) - new Date(a.solved_at))
            .slice(0, 5);

        // Add solved count to user object
        user.solved = solvedChallenges.length;

        res.render('profile', {
            title: 'My Profile | VUW CTF',
            activePage: 'profile',
            user,
            userRank,
            totalUsers,
            totalChallenges: allChallenges.length,
            solvedCount: solvedChallenges.length,
            categoryStats,
            recentlySolved,
            userStreak
        });
    } catch (error) {
        console.error('Profile error:', error);
        req.flash('error_msg', 'An error occurred while loading your profile');
        res.redirect('/');
    }
});

// Update profile route
app.post('/profile/update', isAuthenticated, async (req, res) => {
    const userId = req.session.user.id;
    const { username, email, current_password, new_password, confirm_password } = req.body;

    try {
        const user = await db.getUserById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/login');
        }

        // Check if username already exists (but ignore current user)
        const existingUser = await db.getUserByUsername(username);
        if (existingUser && existingUser.id !== userId) {
            req.flash('error_msg', 'Username already exists');
            return res.redirect('/profile');
        }

        // Check if email already exists (but ignore current user)
        const existingEmail = await db.getUserByEmail(email);
        if (existingEmail && existingEmail.id !== userId) {
            req.flash('error_msg', 'Email already in use');
            return res.redirect('/profile');
        }

        // Update basic info
        await db.updateUserInfo(userId, username, email);

        // Update session
        req.session.user.username = username;

        // Handle password change if requested
        if (current_password && new_password) {
            // Passwords don't match
            if (new_password !== confirm_password) {
                req.flash('error_msg', 'New passwords do not match');
                return res.redirect('/profile');
            }

            // Verify current password
            const isMatch = await bcrypt.compare(current_password, user.password);

            if (!isMatch) {
                req.flash('error_msg', 'Current password is incorrect');
                return res.redirect('/profile');
            }

            // Update password
            await db.updateUserPassword(userId, new_password);
            req.flash('success_msg', 'Password updated successfully');
        }

        req.flash('success_msg', 'Profile updated successfully');
        res.redirect('/profile');
    } catch (error) {
        console.error('Profile update error:', error);
        req.flash('error_msg', 'An error occurred while updating your profile');
        res.redirect('/profile');
    }
});

// Delete account route
app.post('/profile/delete', isAuthenticated, async (req, res) => {
    const userId = req.session.user.id;
    const { password } = req.body;

    try {
        const user = await db.getUserById(userId);

        if (!user) {
            req.flash('error_msg', 'User not found');
            return res.redirect('/profile');
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            req.flash('error_msg', 'Password is incorrect');
            return res.redirect('/profile');
        }

        // Delete user and related data
        await db.deleteUser(userId);

        // Destroy session
        req.session.destroy();

        res.redirect('/?deleted=true');
    } catch (error) {
        console.error('Account deletion error:', error);
        req.flash('error_msg', 'An error occurred while deleting your account');
        res.redirect('/profile');
    }
});

app.get('/instructions', (req, res) => {
  res.render('instructions', {
    title: 'Getting Started | VUW CTF',
    activePage: 'instructions'
  });
});

// Admin routes
app.get('/admin', isAdmin, async (req, res) => {
    try {
        const users = await db.getAllUsers();
        const challenges = await db.getChallenges();
        const systemSettings = await db.getSystemSettings();

        res.render('admin/dashboard', {
            title: 'Admin Dashboard | VUW CTF',
            activePage: 'admin',
            users,
            challenges,
            systemSettings
        });
    } catch (error) {
        console.error('Admin dashboard error:', error);
        req.flash('error_msg', 'Error loading admin dashboard');
        res.redirect('/');
    }
});

// Admin users routes
app.get('/admin/users', isAdmin, async (req, res) => {
    try {
        const users = await db.getAllUsers();
        const challenges = await db.getChallenges();
        
        // Get solved challenges for each user
        const usersWithChallenges = await Promise.all(users.map(async user => {
            const solvedChallenges = await db.getSolvedChallenges(user.id);
            return {
                ...user,
                solvedChallenges
            };
        }));

        res.render('admin/users', {
            title: 'User Management | VUW CTF',
            activePage: 'admin',
            users: usersWithChallenges,
            challenges
        });
    } catch (error) {
        console.error('Admin users error:', error);
        req.flash('error_msg', 'Error loading users');
        res.redirect('/admin');
    }
});

app.post('/admin/users/:id/delete', isAdmin, async (req, res) => {
    try {
        await db.deleteUser(req.params.id);
        req.flash('success_msg', 'User deleted successfully');
    } catch (error) {
        console.error('Delete user error:', error);
        req.flash('error_msg', 'Error deleting user');
    }
    res.redirect('/admin/users');
});

app.post('/admin/users/:id/set-admin', isAdmin, async (req, res) => {
    try {
        await db.updateUserAdminStatus(req.params.id, true);
        req.flash('success_msg', 'User has been set as admin');
    } catch (error) {
        console.error('Set admin error:', error);
        req.flash('error_msg', 'Error setting user as admin');
    }
    res.redirect('/admin/users');
});

app.post('/admin/users/:id/remove-admin', isAdmin, async (req, res) => {
    try {
        await db.updateUserAdminStatus(req.params.id, false);
        req.flash('success_msg', 'Admin privileges have been removed');
    } catch (error) {
        console.error('Remove admin error:', error);
        req.flash('error_msg', 'Error removing admin privileges');
    }
    res.redirect('/admin/users');
});

// Admin user challenge management routes
app.post('/admin/users/:id/challenges/:challengeId/add', isAdmin, async (req, res) => {
    try {
        await db.addUserChallenge(req.params.id, req.params.challengeId);
        req.flash('success_msg', 'Challenge added to user');
    } catch (error) {
        console.error('Add user challenge error:', error);
        req.flash('error_msg', 'Error adding challenge to user');
    }
    res.redirect('/admin/users');
});

app.post('/admin/users/:id/challenges/:challengeId/remove', isAdmin, async (req, res) => {
    try {
        await db.removeUserChallenge(req.params.id, req.params.challengeId);
        req.flash('success_msg', 'Challenge removed from user');
    } catch (error) {
        console.error('Remove user challenge error:', error);
        req.flash('error_msg', 'Error removing challenge from user');
    }
    res.redirect('/admin/users');
});

// Admin challenges routes
app.get('/admin/challenges', isAdmin, async (req, res) => {
    try {
        const challenges = await db.getChallenges();
        res.render('admin/challenges', {
            title: 'Challenge Management | VUW CTF',
            activePage: 'admin',
            challenges
        });
    } catch (error) {
        console.error('Admin challenges error:', error);
        req.flash('error_msg', 'Error loading challenges');
        res.redirect('/admin');
    }
});

app.post('/admin/challenges/create', isAdmin, async (req, res) => {
    try {
        const { name, description, flag, points, category } = req.body;
        await db.createChallenge({ name, description, flag, points, category });
        req.flash('success_msg', 'Challenge created successfully');
    } catch (error) {
        console.error('Create challenge error:', error);
        req.flash('error_msg', 'Error creating challenge');
    }
    res.redirect('/admin/challenges');
});

app.post('/admin/challenges/:id/update', isAdmin, async (req, res) => {
    try {
        const { name, description, flag, points, category } = req.body;
        await db.updateChallenge(req.params.id, { name, description, flag, points, category });
        req.flash('success_msg', 'Challenge updated successfully');
    } catch (error) {
        console.error('Update challenge error:', error);
        req.flash('error_msg', 'Error updating challenge');
    }
    res.redirect('/admin/challenges');
});

app.post('/admin/challenges/:id/delete', isAdmin, async (req, res) => {
    try {
        await db.deleteChallenge(req.params.id);
        req.flash('success_msg', 'Challenge deleted successfully');
    } catch (error) {
        console.error('Delete challenge error:', error);
        req.flash('error_msg', 'Error deleting challenge');
    }
    res.redirect('/admin/challenges');
});

// Admin settings routes
app.get('/admin/settings', isAdmin, async (req, res) => {
    try {
        const settings = await db.getSystemSettings();
        res.render('admin/settings', {
            title: 'System Settings | VUW CTF',
            activePage: 'admin',
            settings
        });
    } catch (error) {
        console.error('Admin settings error:', error);
        req.flash('error_msg', 'Error loading settings');
        res.redirect('/admin');
    }
});

app.post('/admin/settings/update', isAdmin, async (req, res) => {
    try {
        const { siteName, maintenanceMode, registrationEnabled, maxPointsPerDay } = req.body;
        await db.updateSystemSettings({
            siteName,
            maintenanceMode: maintenanceMode === 'on',
            registrationEnabled: registrationEnabled === 'on',
            maxPointsPerDay: parseInt(maxPointsPerDay)
        });
        req.flash('success_msg', 'Settings updated successfully');
    } catch (error) {
        console.error('Settings update error:', error);
        req.flash('error_msg', 'Error updating settings');
    }
    res.redirect('/admin/settings');
});

// Guest user routes
app.get('/guest-login', async (req, res) => {
    try {
        // Create a new guest user
        const guestUser = await db.createGuestUser();
        
        // Create session
        req.session.user = {
            id: guestUser.id,
            username: guestUser.username,
            points: 0,
            isAdmin: false,
            isGuest: true
        };
        
        req.flash('success_msg', 'Welcome! You are now logged in as a guest user.');
        res.redirect('/challenges');
    } catch (error) {
        console.error('Guest login error:', error);
        req.flash('error_msg', 'Error creating guest account');
        res.redirect('/login');
    }
});

// Reset guest progress route
app.post('/reset-guest-progress', isAuthenticated, async (req, res) => {
    try {
        // Only allow guest users to reset their progress
        if (!req.session.user.isGuest) {
            req.flash('error_msg', 'Only guest users can reset their progress');
            return res.redirect('/profile');
        }

        // Clear all solved challenges for the guest user
        await db.clearUserSolves(req.session.user.id);
        
        // Reset points to 0
        await db.updateUserPoints(req.session.user.id, -req.session.user.points);
        
        // Update session
        req.session.user.points = 0;
        
        req.flash('success_msg', 'Your progress has been reset');
        res.redirect('/profile');
    } catch (error) {
        console.error('Reset progress error:', error);
        req.flash('error_msg', 'Error resetting progress');
        res.redirect('/profile');
    }
});

// Catch-all route for non-existent URLs
app.use((req, res) => {
    res.redirect('/');
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Server accessible via public IP at port ${PORT}`);
}); 