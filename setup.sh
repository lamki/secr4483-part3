#!/bin/bash

echo "🚀 Initializing Secure Application Workspace..."

echo "📦 Creating configuration and source files..."

# 2. Generate package.json
cat << 'EOF' > package.json
{
  "name": "secr4483-secure-app",
  "version": "1.0.0",
  "description": "Integrated Secure Application for SECR4483",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {}
}
EOF

echo "⚡ Installing production dependencies..."
npm install express mysql2 express-session bcrypt helmet express-validator

echo "✅ Setup Complete!"
echo "👉 Step 1: Import schema.sql into MySQL Server."
echo "👉 Step 2: Run 'npm start' to run the application securely."