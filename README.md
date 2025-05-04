# Victoria University of Wellington CTF Website

A simple Node.js website for the Victoria University of Wellington Capture The Flag (VUW CTF) group.

## Description

This website provides information about the VUW CTF group, including:

- About the group and what is CTF
- Upcoming and past events
- Resources for learning cybersecurity
- Contact information

## Technologies Used

- Node.js
- Express.js
- EJS templating engine
- Bootstrap 5
- JavaScript

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/yourusername/vuwctf.git
   cd vuwctf
   ```

2. Install dependencies:

   ```
   npm install
   ```

3. Start the server:
   ```
   npm start
   ```

The website will be available at [http://localhost:3000](http://localhost:3000).

## Development

To run the website in development mode with automatic restart:

```
npm run dev
```

## Project Structure

- `app.js` - Main application file
- `views/` - EJS templates
  - `layouts/` - Layout templates
  - `partials/` - Reusable components (header, footer)
- `public/` - Static assets
  - `css/` - Stylesheets
  - `js/` - JavaScript files
  - `images/` - Images

## License

ISC
