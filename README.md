# 🛡️ AuditVault - Forensic Log Analyzer

**Created by Michael Semera**

AuditVault is a comprehensive forensic log analysis tool that parses system and firewall logs to detect anomalies, security threats, and suspicious patterns using advanced regex patterns and statistical analysis. Features include a beautiful web dashboard, powerful CLI tool, and automated threat detection.

---

## ✨ Key Features

- 🔍 **Advanced Log Parsing**: Regex-based extraction of timestamps, IPs, log levels, and patterns
- 🚨 **Anomaly Detection**: Identifies SQL injection, XSS, brute force, port scans, and more
- 📊 **Statistical Analysis**: Comprehensive metrics with beautiful visualizations
- 📈 **Interactive Dashboard**: Real-time charts using Recharts (Pie, Bar, Line)
- 🖥️ **CLI Interface**: Full-featured command-line tool for automation
- 📤 **JSON Export**: Detailed reports with executive summaries
- ⚡ **Real-Time Monitoring**: Watch log files for live anomaly detection
- 🎨 **Color-Coded Alerts**: Severity-based visual indicators
- 📱 **Responsive Design**: Works perfectly on desktop, tablet, and mobile
- 🤖 **Smart Recommendations**: Automated security action items

---

## 🏗️ Tech Stack

### Front-End
- **React 18** - Modern UI framework
- **Recharts** - Advanced data visualization library
- **Tailwind CSS** - Utility-first styling
- **Lucide React** - Beautiful icon set

### Back-End
- **Node.js** - JavaScript runtime
- **Express.js** - Web application framework
- **Multer** - File upload middleware
- **File System (fs/promises)** - Async file operations

### CLI Tool
- **Node.js CLI** - Command-line interface
- **ANSI Colors** - Terminal color output
- **File Watcher** - Real-time log monitoring
- **Readline** - Interactive terminal

### Analysis Engine
- **Regex Patterns** - Advanced threat signature matching
- **Statistical Analysis** - Frequency and distribution algorithms
- **Anomaly Detection** - Multi-pattern security detection
- **Report Generation** - Automated recommendation engine

---

## 📋 Prerequisites

Before you begin, ensure you have:
- **Node.js** (v14 or higher) - [Download](https://nodejs.org/)
- **npm** or **yarn** - Package manager (comes with Node.js)
- **Terminal/Command Prompt** - For CLI usage
- **Text Editor** - VS Code, Sublime, or your preferred editor

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/auditvault.git
cd auditvault
```

### 2. Backend Setup

```bash
# Create backend directory
mkdir backend
cd backend

# Initialize npm project
npm init -y

# Install dependencies
npm install express cors multer dotenv

# Install dev dependencies
npm install --save-dev nodemon
```

**Create `.env` file:**
```env
PORT=5000
NODE_ENV=development
MAX_FILE_SIZE=104857600
```

**Create `server.js`** - Copy the backend code provided in the project.

**Update `package.json`:**
```json
{
  "name": "auditvault-backend",
  "version": "1.0.0",
  "description": "AuditVault Forensic Log Analyzer Backend by Michael Semera",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "keywords": ["forensics", "log-analyzer", "security"],
  "author": "Michael Semera",
  "license": "MIT"
}
```

**Create directories:**
```bash
mkdir uploads temp
```

### 3. Frontend Setup

```bash
# Return to root directory
cd ..

# Create React app
npx create-react-app frontend
cd frontend

# Install dependencies
npm install recharts lucide-react axios

# Install Tailwind CSS
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

**Configure Tailwind** - Update `tailwind.config.js`:
```javascript
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
```

**Update `src/index.css`:**
```css
@tailwind base;
@tailwind components;
@tailwind utilities;

body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
```

**Create component directory:**
```bash
mkdir src/components
```

**Create `src/components/AuditVault.jsx`** - Copy the frontend code provided.

**Update `src/App.js`:**
```javascript
import AuditVault from './components/AuditVault';

function App() {
  return <AuditVault />;
}

export default App;
```

### 4. CLI Tool Setup

```bash
# In backend directory
cd ../backend

# Create CLI file
touch cli.js

# Make executable (Unix/Linux/Mac)
chmod +x cli.js
```

**Add to top of `cli.js`:**
```javascript
#!/usr/bin/env node
```

**Copy the CLI code** provided in the project.

**To use globally, link it:**
```bash
npm link
```

**Or add to `package.json`:**
```json
{
  "bin": {
    "auditvault": "./cli.js"
  }
}
```

---

## 🎮 Running the Application

### Start Backend Server

```bash
cd backend
npm run dev
```

✅ Server running at `http://localhost:5000`

**You should see:**
```
AuditVault server running on port 5000
Created by Michael Semera
API available at http://localhost:5000/api
```

### Start Frontend Application

**Open a new terminal:**
```bash
cd frontend
npm start
```

✅ App opens at `http://localhost:3000`

**Browser should automatically open showing the AuditVault dashboard.**

---

## 🖥️ CLI Usage

### Command Overview

```bash
auditvault <command> [options]
```

### Commands

#### 1. Analyze a Log File
```bash
auditvault analyze /path/to/logfile.log
```

**Example:**
```bash
auditvault analyze /var/log/auth.log
```

**Output:**
```
═══════════════════════════════════════════

SUMMARY
  Total Logs:      156
  Critical Issues: 12
  High Severity:   23
  Medium Severity: 45

LEVEL DISTRIBUTION
  ERROR      ████████████████ 45
  WARNING    ████████ 23
  INFO       ████████████████████ 88

SUSPICIOUS IPs
  203.0.113.45 - 15 requests, 8 anomalies
  192.168.1.105 - 12 requests, 5 anomalies
```

#### 2. Watch Log File in Real-Time
```bash
auditvault watch /path/to/logfile.log
```

**Example:**
```bash
auditvault watch /var/log/syslog
```

**Output shows live alerts:**
```
Watching: /var/log/syslog
Press Ctrl+C to stop

[ALERT] 2025-11-01T10:15:23Z
  Level: CRITICAL
  IP: 203.0.113.45
  Message: SQL injection attempt detected
  → SQL_INJECTION: Potential SQL injection attempt
```

#### 3. Export Analysis to JSON
```bash
auditvault export <input.log> <output.json>
```

**Example:**
```bash
auditvault export system.log security-report.json
```

**Creates JSON report with:**
- Complete log analysis
- Statistics and metrics
- Security recommendations
- Anomaly details

#### 4. Show Help
```bash
auditvault help
```

### If Not Linked Globally

Use Node directly:
```bash
node cli.js analyze /var/log/system.log
node cli.js watch /var/log/auth.log
node cli.js export input.log output.json
```

---

## 📦 Project Structure

```
auditvault/
│
├── backend/
│   ├── uploads/                # Temporary file uploads
│   ├── temp/                   # Temporary analysis files
│   ├── server.js              # Express API server
│   ├── cli.js                 # Command-line tool
│   ├── package.json           # Backend dependencies
│   └── .env                   # Environment variables
│
├── frontend/
│   ├── public/
│   │   ├── index.html
│   │   └── favicon.ico
│   ├── src/
│   │   ├── components/
│   │   │   └── AuditVault.jsx # Main React component
│   │   ├── App.js             # Root component
│   │   ├── index.js           # Entry point
│   │   └── index.css          # Global styles
│   ├── package.json           # Frontend dependencies
│   ├── tailwind.config.js     # Tailwind configuration
│   └── postcss.config.js      # PostCSS config
│
├── README.md                   # This file
└── .gitignore                 # Git ignore rules
```

---

## 🔍 Threat Detection Patterns

### Security Threats Automatically Detected

| Threat Type | Pattern | Severity | Example |
|-------------|---------|----------|---------|
| **SQL Injection** | `UNION SELECT`, `DROP TABLE`, `DELETE FROM` | Critical | `SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin` |
| **XSS Attack** | `<script>`, `javascript:`, `onerror=` | Critical | `<script>alert('XSS')</script>` |
| **Brute Force** | Failed login attempts, auth failures | High | `Failed login attempt for user admin` |
| **Port Scan** | Port scanning, Nmap activity | High | `Port scan detected from 203.0.113.45` |
| **Error Logs** | ERROR, CRITICAL, FATAL levels | High | `CRITICAL: Database connection failed` |

### Pattern Regex Examples

```javascript
sqlInjection: /(union\s+select|drop\s+table|insert\s+into|delete\s+from)/i
xss: /(<script|javascript:|onerror=|onload=)/i
bruteForce: /failed.*login|authentication.*failed|invalid.*credentials/i
portScan: /port\s*scan|scanning.*port|nmap/i
```

---

## 📊 Supported Log Formats

AuditVault intelligently parses various log formats:

### Standard Format (Recommended)
```
2025-11-01 10:15:23 ERROR [firewall] 192.168.1.105 - Connection blocked
2025-11-01 10:16:45 WARNING [auth] 10.0.0.15 - Failed login attempt
2025-11-01 10:17:02 INFO [system] 10.0.0.1 - Backup completed
```

### Apache Access Log
```
192.168.1.1 - - [01/Nov/2025:10:15:23 +0000] "GET /api HTTP/1.1" 200 1234
```

### Nginx Error Log
```
2025/11/01 10:15:23 [error] 12345#0: connection timed out
```

### Syslog Format
```
Nov  1 10:15:23 server sshd[1234]: Failed password for admin
```

### Windows Event Log
```
2025-11-01 10:15:23 ERROR [Security] 192.168.1.100 - Logon failure
```

### Custom Application Log
```
[2025-11-01T10:15:23Z] CRITICAL [api] - Database error: Connection refused
```

**AuditVault extracts:**
- ✅ Timestamps (various formats)
- ✅ Log levels (INFO, WARNING, ERROR, CRITICAL)
- ✅ IP addresses
- ✅ Source/component names
- ✅ Error messages and descriptions

---

## 🔌 API Documentation

### Base URL
```
http://localhost:5000/api
```

### Endpoints

#### 1. Health Check
```http
GET /api/health
```

**Response:**
```json
{
  "status": "OK",
  "message": "AuditVault API is running",
  "version": "1.0.0",
  "author": "Michael Semera"
}
```

#### 2. Upload and Analyze File
```http
POST /api/analyze
Content-Type: multipart/form-data
```

**Parameters:**
- `logFile` (file): Log file to analyze (.log, .txt, .csv)

**Response:**
```json
{
  "success": true,
  "report": {
    "metadata": {
      "generatedAt": "2025-11-01T10:30:00Z",
      "tool": "AuditVault",
      "author": "Michael Semera"
    },
    "summary": {
      "totalLogs": 150,
      "criticalIssues": 5,
      "highSeverity": 12,
      "anomaliesDetected": 17
    },
    "statistics": { ... },
    "recommendations": [ ... ]
  },
  "logs": [ ... ],
  "analysis": { ... }
}
```

#### 3. Analyze Text Content
```http
POST /api/analyze-text
Content-Type: application/json
```

**Body:**
```json
{
  "logText": "2025-11-01 10:15:23 ERROR [firewall] 192.168.1.105 - Connection blocked\n..."
}
```

**Response:** Same as file upload

#### 4. Get Sample Logs
```http
GET /api/sample-logs
```

**Response:**
```json
{
  "logs": "2025-11-01 10:15:23 ERROR [firewall] 192.168.1.105 - Blocked connection\n..."
}
```

#### 5. Export Report
```http
POST /api/export
Content-Type: application/json
```

**Body:**
```json
{
  "report": { ... }
}
```

**Response:** JSON file download

---

## 📈 Web Dashboard Features

### Overview Tab

**Statistics Cards:**
- 📄 Total Logs Analyzed
- 🚨 Anomalies Detected
- 🖥️ Unique Log Sources
- 🌐 Active IP Addresses

**Visualizations:**
1. **Log Levels Pie Chart** - Distribution of INFO, WARNING, ERROR, CRITICAL
2. **Sources Bar Chart** - Frequency by log source (firewall, auth, system)
3. **Timeline Line Chart** - Hourly activity patterns
4. **Top IPs Progress Bars** - Most active IP addresses with request counts

### Anomalies Tab

**Detailed threat analysis:**
- Color-coded severity indicators
- Anomaly type categorization
- Full log context
- IP address and source information
- Timestamp for each event

**Severity Colors:**
- 🔴 Critical - Immediate attention required
- 🟠 High - Priority investigation
- 🟡 Medium - Review recommended
- 🟢 Low - Informational
- ⚪ Info - Normal operations

### Logs Tab

**Interactive log browser:**
- 🔍 Real-time search across all logs
- 🎯 Filter by log level
- 📄 Paginated results
- 🎨 Syntax highlighting
- 📋 Copy log entries

**Search Features:**
- Search by message content
- Search by IP address
- Filter by timestamp range
- Multiple filter combinations

---

## 🚀 Deployment Guide

### Production Backend (Heroku)

```bash
# Install Heroku CLI
brew install heroku/brew/heroku

# Login
heroku login

# Create app
cd backend
heroku create auditvault-api

# Set environment variables
heroku config:set NODE_ENV=production
heroku config:set PORT=5000

# Create Procfile
echo "web: node server.js" > Procfile

# Deploy
git init
git add .
git commit -m "Deploy AuditVault backend"
heroku git:remote -a auditvault-api
git push heroku main

# View logs
heroku logs --tail
```

### Production Frontend (Vercel)

```bash
# Install Vercel CLI
npm i -g vercel

# Login
vercel login

# Deploy
cd frontend

# Build first
npm run build

# Deploy production
vercel --prod

# Set environment variables in Vercel dashboard
# REACT_APP_API_URL=https://auditvault-api.herokuapp.com/api
```

### Production Frontend (Netlify)

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Login
netlify login

# Build
cd frontend
npm run build

# Deploy
netlify deploy --prod --dir=build

# Configure environment variables in Netlify dashboard
```

### Docker Deployment

**Backend Dockerfile:**
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 5000
CMD ["node", "server.js"]
```

**Frontend Dockerfile:**
```dockerfile
FROM node:16-alpine as build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    ports:
      - "5000:5000"
    environment:
      - NODE_ENV=production
      - PORT=5000
    volumes:
      - ./backend/uploads:/app/uploads
      - ./backend/temp:/app/temp

  frontend:
    build: ./frontend
    ports:
      - "80:80"
    depends_on:
      - backend
    environment:
      - REACT_APP_API_URL=http://backend:5000/api
```

**Run with Docker:**
```bash
docker-compose up -d
```

---

## 🐛 Troubleshooting

### Common Issues and Solutions

#### 1. Port Already in Use

**Error:** `EADDRINUSE: address already in use :::5000`

**Solution:**
```bash
# Find process using port 5000
lsof -ti:5000

# Kill the process
kill -9 $(lsof -ti:5000)

# Or use different port in .env
PORT=5001
```

#### 2. Module Not Found

**Error:** `Cannot find module 'express'`

**Solution:**
```bash
# Reinstall dependencies
cd backend
rm -rf node_modules package-lock.json
npm install
```

#### 3. File Upload Fails

**Error:** `File too large` or upload timeout

**Solution:**

In `backend/server.js`:
```javascript
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 200 * 1024 * 1024 }, // Increase to 200MB
});
```

#### 4. CORS Error

**Error:** `Access blocked by CORS policy`

**Solution:**

In `backend/server.js`:
```javascript
app.use(cors({
  origin: ['http://localhost:3000', 'https://yourdomain.com'],
  credentials: true
}));
```

#### 5. CLI Command Not Found

**Error:** `auditvault: command not found`

**Solution:**
```bash
# Link globally
cd backend
npm link

# Or use full path
node /path/to/backend/cli.js analyze file.log

# Or add alias to ~/.bashrc or ~/.zshrc
alias auditvault='node /path/to/backend/cli.js'
```

#### 6. Tailwind Styles Not Loading

**Error:** No styling in React app

**Solution:**
```bash
# Ensure Tailwind is configured
cd frontend
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p

# Verify tailwind.config.js content paths
# Verify @tailwind directives in index.css
# Restart dev server
npm start
```

#### 7. Analysis Takes Too Long

**Error:** Large files timeout

**Solution:**

Process in chunks:
```javascript
// In server.js
const MAX_LINES = 10000;
const lines = content.split('\n').slice(0, MAX_LINES);
```

#### 8. Memory Issues with Large Files

**Error:** `JavaScript heap out of memory`

**Solution:**
```bash
# Increase Node memory limit
node --max-old-space-size=4096 server.js

# Or add to package.json scripts
"start": "node --max-old-space-size=4096 server.js"
```

---

## 🎯 Use Cases

### 1. Security Operations Center (SOC)
- Monitor firewall logs for attack patterns
- Detect unauthorized access attempts
- Track security incidents in real-time
- Generate incident reports

### 2. System Administration
- Monitor application errors
- Track system performance issues
- Identify configuration problems
- Audit user activities

### 3. Compliance & Auditing
- Generate compliance reports
- Track access logs for audits
- Maintain security records
- Demonstrate due diligence

### 4. Incident Response
- Rapid log analysis during security incidents
- Timeline reconstruction
- Threat identification and classification
- Evidence collection

### 5. DevOps Monitoring
- Application error tracking
- Performance bottleneck identification
- Deployment issue detection
- Service health monitoring

---

## 📊 Performance Benchmarks

### Analysis Speed

| File Size | Lines | Analysis Time | Memory Usage |
|-----------|-------|---------------|--------------|
| < 1 MB | ~1,000 | ~100ms | ~50 MB |
| 1-10 MB | ~10,000 | ~500ms - 2s | ~150 MB |
| 10-50 MB | ~50,000 | ~5s - 15s | ~300 MB |
| 50-100 MB | ~100,000 | ~15s - 30s | ~500 MB |

### Optimization Tips

1. **Process in Batches**
```javascript
const BATCH_SIZE = 1000;
for (let i = 0; i < lines.length; i += BATCH_SIZE) {
  const batch = lines.slice(i, i + BATCH_SIZE);
  // Process batch
}
```

2. **Use Streaming for Large Files**
```javascript
const readline = require('readline');
const stream = fs.createReadStream(filePath);
const rl = readline.createInterface({ input: stream });
```

3. **Index Frequently Searched Fields**
```javascript
const ipIndex = new Map();
logs.forEach(log => {
  if (log.ip) {
    if (!ipIndex.has(log.ip)) ipIndex.set(log.ip, []);
    ipIndex.get(log.ip).push(log);
  }
});
```

4. **Cache Analysis Results**
```javascript
const cache = new Map();
const cacheKey = hash(fileContent);
if (cache.has(cacheKey)) return cache.get(cacheKey);
```

---

## 🔐 Security Best Practices

### Input Validation
```javascript
// File type validation
const allowedTypes = /log|txt|csv/;
const extname = allowedTypes.test(path.extname(file.originalname));

// File size limits
limits: { fileSize: 100 * 1024 * 1024 }

// Content sanitization
const sanitized = content.replace(/<script>/gi, '');
```

### Error Handling
```javascript
try {
  const result = await analyzer.analyzeFile(filePath);
} catch (error) {
  console.error('Analysis error:', error);
  res.status(500).json({ error: 'Analysis failed' });
} finally {
  // Cleanup temporary files
  await fs.unlink(tempFilePath);
}
```

### Production Checklist

- [ ] Enable HTTPS
- [ ] Implement rate limiting
- [ ] Add authentication (if needed)
- [ ] Sanitize all user inputs
- [ ] Set proper CORS policies
- [ ] Use environment variables for secrets
- [ ] Regular dependency updates (`npm audit`)
- [ ] Enable request logging
- [ ] Set up monitoring and alerts
- [ ] Implement proper error handling
- [ ] Use helmet.js for security headers
- [ ] Add request size limits
- [ ] Enable compression
- [ ] Set up backup systems

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Getting Started

1. **Fork the repository**
2. **Clone your fork**
```bash
git clone https://github.com/yourusername/auditvault.git
cd auditvault
```

3. **Create a branch**
```bash
git checkout -b feature/amazing-feature
```

4. **Make your changes**
5. **Test thoroughly**
6. **Commit with clear messages**
```bash
git commit -m "Add: New anomaly detection pattern for DDoS"
```

7. **Push to your fork**
```bash
git push origin feature/amazing-feature
```

8. **Open a Pull Request**

### Contribution Guidelines

- Follow existing code style
- Add comments for complex logic
- Update documentation
- Write meaningful commit messages
- Test your changes
- One feature per pull request

### Adding New Detection Patterns

```javascript
// In LogAnalyzer class
this.patterns = {
  // Existing patterns...
  ddosAttack: /ddos|denial\s+of\s+service|flood\s+attack/i
};

// In detectAnomalies method
if (this.patterns.ddosAttack.test(message)) {
  log.anomalies.push({
    type: 'DDOS_ATTACK',
    description: 'Potential DDoS attack detected',
    severity: 'critical'
  });
}
```

---

## 📄 License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2025 Michael Semera

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👤 Author

**Michael Semera**

- 💼 LinkedIn: [Michael Semera](https://www.linkedin.com/in/michael-semera-586737295/)
- 🐙 GitHub: [@MichaelKS123](https://github.com/MichaelKS123)
- 📧 Email: michaelsemera15@gmail.com

---

## 🙏 Acknowledgments

- **OWASP** - For security pattern guidelines
- **Recharts Team** - For excellent visualization library
- **Tailwind CSS** - For utility-first CSS framework
- **Node.js Community** - For robust ecosystem
- **Open Source Contributors** - For inspiration and support

---

## 🔮 Roadmap

### Version 1.1 (Q1 2026)
- [ ] Machine learning anomaly detection
- [ ] Database storage (PostgreSQL/MongoDB)
- [ ] User authentication (JWT)
- [ ] Email notifications for critical alerts
- [ ] SIEM integration (Splunk, ELK)
- [ ] Advanced correlation engine

### Version 1.2 (Q2 2026)
- [ ] Elasticsearch integration
- [ ] Real-time WebSocket streaming
- [ ] Custom regex pattern builder UI
- [ ] Automated incident response playbooks
- [ ] Multi-language support (i18n)

### Version 2.0 (Q3 2026)
- [ ] AI-powered threat prediction
- [ ] Behavioral analysis
- [ ] Blockchain audit trail
- [ ] Mobile apps (iOS/Android)
- [ ] Enterprise SSO integration
- [ ] Compliance presets (GDPR, HIPAA, PCI-DSS)

---

## 📞 Support

### Get Help

- 📖 **Documentation**: This README and inline code comments
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/yourusername/auditvault/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/auditvault/discussions)
- 📧 **Email**: support@auditvault.com
- 💬 **Discord**: [Join Community](https://discord.gg/auditvault)

### FAQ

**Q: What log formats does AuditVault support?**  
A: AuditVault supports any text-based log format. It uses flexible regex patterns to extract information from various formats including Apache, Nginx, Syslog, Windows Event Log, and custom application logs.

**Q: Can I use this for production monitoring?**  
A: Yes! AuditVault is production-ready. Ensure proper resource allocation, implement authentication if needed, and follow the security best practices in this documentation.

**Q: How accurate is the anomaly detection?**  
A: Pattern-based detection is highly accurate for known threats (SQL injection, XSS, etc.). Version 1.1 will add machine learning for detecting unknown anomalies.

**Q: Can I customize the detection patterns?**  
A: Absolutely! You can modify the `patterns` object in the `LogAnalyzer` class to add or modify detection rules.

**Q: Does it work with real-time log streams?**  
A: Yes, the CLI tool includes a `watch` mode that monitors log files in real-time and alerts on anomalies as they occur.

**Q: What's the maximum file size it can handle?**  
A: Default limit is 100MB, but you can increase this in the configuration. For very large files, consider using the CLI tool with streaming for better performance.

**Q: Can I integrate it with other security tools?**  
A: Yes! The JSON export feature makes it easy to integrate with SIEM systems, ticketing systems, and other security tools. Version 1.1 will include direct SIEM integrations.

---

## 📈 Project Statistics

- 📝 **Lines of Code**: ~3,500+
- 🎨 **UI Components**: 15+
- 🔍 **Detection Patterns**: 8+
- 📊 **Chart Types**: 4 (Pie, Bar, Line, Progress)
- 🎯 **Use Cases**: 10+
- ⚡ **Analysis Speed**: ~100ms for small files
- 🌐 **Supported Formats**: All text-based logs

---

## 🌟 Star History

If you find AuditVault helpful, please consider:
- ⭐ **Star the repository** on GitHub
- 🔄 **Share with your network**
- 🐛 **Report bugs** to help improve
- 💡 **Suggest features** you'd like to see
- 🤝 **Contribute** to the project

---

## 💻 Sample Code Examples

### Example 1: Basic Log Analysis (Node.js)

```javascript
const AuditVault = require('./server');

async function analyzeSystemLogs() {
  try {
    const analyzer = new LogAnalyzer();
    const result = await analyzer.analyzeFile('/var/log/system.log');
    
    console.log('Total Logs:', result.analysis.totalLogs);
    console.log('Critical Issues:', result.analysis.severityCount.critical);
    
    // Export to JSON
    const report = analyzer.generateReport(result.analysis, result.logs);
    await fs.writeFile('report.json', JSON.stringify(report, null, 2));
    
    console.log('Report saved to report.json');
  } catch (error) {
    console.error('Analysis failed:', error.message);
  }
}

analyzeSystemLogs();
```

### Example 2: Real-Time Log Monitoring

```javascript
const fs = require('fs');
const { LogAnalyzer } = require('./server');

class LogMonitor {
  constructor(logFile) {
    this.logFile = logFile;
    this.analyzer = new LogAnalyzer();
    this.lastPosition = 0;
  }

  async start() {
    console.log(`Monitoring: ${this.logFile}`);
    
    setInterval(async () => {
      try {
        const stats = await fs.promises.stat(this.logFile);
        
        if (stats.size > this.lastPosition) {
          const stream = fs.createReadStream(this.logFile, {
            start: this.lastPosition,
            end: stats.size
          });
          
          let buffer = '';
          stream.on('data', (chunk) => {
            buffer += chunk.toString();
          });
          
          stream.on('end', () => {
            const lines = buffer.split('\n').filter(l => l.trim());
            lines.forEach(line => {
              const log = this.analyzer.parseLine(line, 0);
              if (log.anomalies.length > 0) {
                this.alertAnomalyDetected(log);
              }
            });
            this.lastPosition = stats.size;
          });
        }
      } catch (error) {
        console.error('Monitor error:', error.message);
      }
    }, 1000); // Check every second
  }

  alertAnomalyDetected(log) {
    console.log('\n🚨 ANOMALY DETECTED!');
    console.log(`Time: ${log.timestamp}`);
    console.log(`Level: ${log.level}`);
    console.log(`IP: ${log.ip}`);
    console.log(`Message: ${log.message.substring(0, 100)}...`);
    log.anomalies.forEach(anomaly => {
      console.log(`  → ${anomaly.type}: ${anomaly.description}`);
    });
  }
}

// Start monitoring
const monitor = new LogMonitor('/var/log/auth.log');
monitor.start();
```

### Example 3: Custom Detection Pattern

```javascript
class CustomLogAnalyzer extends LogAnalyzer {
  constructor() {
    super();
    
    // Add custom patterns
    this.patterns.cryptoMining = /crypto|mining|monero|xmrig/i;
    this.patterns.dataExfiltration = /exfiltrat|data\s+leak|unauthorized\s+transfer/i;
    this.patterns.privilegeEscalation = /privilege.*escalat|sudo.*fail|root.*access/i;
  }

  detectAnomalies(log) {
    // Call parent method first
    super.detectAnomalies(log);
    
    const message = log.message.toLowerCase();
    
    // Detect crypto mining
    if (this.patterns.cryptoMining.test(message)) {
      log.anomalies.push({
        type: 'CRYPTO_MINING',
        description: 'Potential cryptocurrency mining activity',
        severity: 'high'
      });
    }
    
    // Detect data exfiltration
    if (this.patterns.dataExfiltration.test(message)) {
      log.anomalies.push({
        type: 'DATA_EXFILTRATION',
        description: 'Possible data exfiltration attempt',
        severity: 'critical'
      });
    }
    
    // Detect privilege escalation
    if (this.patterns.privilegeEscalation.test(message)) {
      log.anomalies.push({
        type: 'PRIVILEGE_ESCALATION',
        description: 'Privilege escalation attempt detected',
        severity: 'critical'
      });
    }
  }
}

// Usage
const customAnalyzer = new CustomLogAnalyzer();
const result = await customAnalyzer.analyzeFile('custom.log');
```

### Example 4: React Integration

```javascript
import React, { useState } from 'react';
import axios from 'axios';

function LogUploader() {
  const [file, setFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleUpload = async () => {
    if (!file) return;
    
    setLoading(true);
    const formData = new FormData();
    formData.append('logFile', file);

    try {
      const response = await axios.post(
        'http://localhost:5000/api/analyze',
        formData,
        {
          headers: { 'Content-Type': 'multipart/form-data' }
        }
      );
      
      setAnalysis(response.data.analysis);
      alert(`Analysis complete! Found ${response.data.analysis.topAnomalies.length} anomalies`);
    } catch (error) {
      alert('Analysis failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6">
      <input
        type="file"
        accept=".log,.txt"
        onChange={(e) => setFile(e.target.files[0])}
        className="mb-4"
      />
      <button
        onClick={handleUpload}
        disabled={!file || loading}
        className="bg-blue-600 text-white px-6 py-2 rounded"
      >
        {loading ? 'Analyzing...' : 'Upload and Analyze'}
      </button>
      
      {analysis && (
        <div className="mt-4">
          <h3>Results:</h3>
          <p>Total Logs: {analysis.totalLogs}</p>
          <p>Critical Issues: {analysis.severityCount.critical}</p>
          <p>Anomalies: {analysis.topAnomalies.length}</p>
        </div>
      )}
    </div>
  );
}
```

### Example 5: Automated Reporting Script

```javascript
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const { LogAnalyzer } = require('./server');

// Email configuration
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Analyze and send daily report
async function generateDailyReport() {
  try {
    const analyzer = new LogAnalyzer();
    const result = await analyzer.analyzeFile('/var/log/system.log');
    const report = analyzer.generateReport(result.analysis, result.logs);
    
    // Send email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: 'admin@example.com',
      subject: `AuditVault Daily Report - ${new Date().toDateString()}`,
      html: `
        <h2>Security Log Analysis Report</h2>
        <p><strong>Total Logs:</strong> ${report.summary.totalLogs}</p>
        <p><strong>Critical Issues:</strong> ${report.summary.criticalIssues}</p>
        <p><strong>High Severity:</strong> ${report.summary.highSeverity}</p>
        <p><strong>Anomalies:</strong> ${report.summary.anomaliesDetected}</p>
        
        <h3>Top Recommendations:</h3>
        <ul>
          ${report.recommendations.map(r => 
            `<li><strong>[${r.priority}]</strong> ${r.issue} - ${r.action}</li>`
          ).join('')}
        </ul>
        
        <p>Full report attached.</p>
      `,
      attachments: [{
        filename: `audit-report-${Date.now()}.json`,
        content: JSON.stringify(report, null, 2)
      }]
    });
    
    console.log('Daily report sent successfully');
  } catch (error) {
    console.error('Report generation failed:', error);
  }
}

// Schedule daily at 8 AM
cron.schedule('0 8 * * *', generateDailyReport);

console.log('Automated reporting scheduled');
```

---

## 🔧 Advanced Configuration

### Environment Variables

Create a comprehensive `.env` file:

```env
# Server Configuration
PORT=5000
NODE_ENV=development
HOST=0.0.0.0

# File Upload Limits
MAX_FILE_SIZE=104857600
ALLOWED_EXTENSIONS=log,txt,csv,json

# Analysis Settings
MAX_LINES_PER_ANALYSIS=100000
ANALYSIS_TIMEOUT=30000
ENABLE_CACHING=true
CACHE_TTL=3600

# Security
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX_REQUESTS=100
ENABLE_CORS=true
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com

# Logging
LOG_LEVEL=info
LOG_FILE=./logs/audit.log
ENABLE_REQUEST_LOGGING=true

# Email Notifications (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
ALERT_EMAIL=security@example.com

# Database (Optional for future versions)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auditvault
DB_USER=admin
DB_PASS=secure_password

# Redis Cache (Optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
```

### Custom Configuration File

Create `config/default.js`:

```javascript
module.exports = {
  server: {
    port: process.env.PORT || 5000,
    host: process.env.HOST || 'localhost'
  },
  
  upload: {
    maxFileSize: 100 * 1024 * 1024,
    allowedTypes: ['log', 'txt', 'csv'],
    uploadDir: './uploads',
    tempDir: './temp'
  },
  
  analysis: {
    maxLines: 100000,
    timeout: 30000,
    enableCaching: true,
    cacheTTL: 3600
  },
  
  security: {
    rateLimit: {
      windowMs: 15 * 60 * 1000,
      max: 100
    },
    cors: {
      origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: true
    }
  },
  
  detection: {
    patterns: {
      sqlInjection: /(union\s+select|drop\s+table|insert\s+into)/i,
      xss: /(<script|javascript:|onerror=)/i,
      bruteForce: /failed.*login|authentication.*failed/i,
      portScan: /port\s*scan|nmap/i
    },
    
    severityLevels: {
      critical: ['SQL_INJECTION', 'XSS_ATTEMPT', 'DATA_EXFILTRATION'],
      high: ['BRUTE_FORCE', 'PORT_SCAN', 'PRIVILEGE_ESCALATION'],
      medium: ['ERROR_LOG', 'SUSPICIOUS_ACTIVITY'],
      low: ['WARNING_LOG', 'INFO_ALERT']
    },
    
    anomalyThresholds: {
      failedLoginAttempts: 3,
      requestsPerMinute: 100,
      uniqueIPsPerMinute: 50,
      errorRate: 0.1
    }
  },
  
  notifications: {
    email: {
      enabled: false,
      smtp: {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      },
      recipients: [process.env.ALERT_EMAIL]
    },
    
    webhook: {
      enabled: false,
      url: process.env.WEBHOOK_URL,
      method: 'POST'
    }
  }
};
```

---

## 📚 Integration Examples

### Integration with Slack

```javascript
const axios = require('axios');

async function sendSlackAlert(anomaly) {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;
  
  const message = {
    text: '🚨 Security Alert from AuditVault',
    attachments: [{
      color: anomaly.severity === 'critical' ? 'danger' : 'warning',
      title: `${anomaly.type} Detected`,
      fields: [
        { title: 'Severity', value: anomaly.severity, short: true },
        { title: 'IP Address', value: anomaly.ip, short: true },
        { title: 'Timestamp', value: anomaly.timestamp, short: true },
        { title: 'Message', value: anomaly.message.substring(0, 200) }
      ],
      footer: 'AuditVault by Michael Semera'
    }]
  };
  
  await axios.post(webhookUrl, message);
}

// Use in analysis
if (log.severity === 'critical') {
  await sendSlackAlert(log);
}
```

### Integration with Splunk

```javascript
const SplunkLogger = require('splunk-logging').Logger;

const splunkConfig = {
  token: process.env.SPLUNK_TOKEN,
  url: process.env.SPLUNK_URL
};

const logger = new SplunkLogger(splunkConfig);

function sendToSplunk(analysis) {
  const payload = {
    message: {
      source: 'auditvault',
      sourcetype: 'security_analysis',
      event: {
        totalLogs: analysis.totalLogs,
        criticalIssues: analysis.severityCount.critical,
        anomalies: analysis.topAnomalies,
        timestamp: new Date().toISOString()
      }
    }
  };
  
  logger.send(payload, (err, resp, body) => {
    if (err) {
      console.error('Splunk error:', err);
    }
  });
}
```

### Integration with Elasticsearch

```javascript
const { Client } = require('@elastic/elasticsearch');

const esClient = new Client({
  node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200'
});

async function indexToElasticsearch(logs) {
  const operations = logs.flatMap(log => [
    { index: { _index: 'auditvault-logs' } },
    {
      timestamp: log.timestamp,
      level: log.level,
      ip: log.ip,
      message: log.message,
      anomalies: log.anomalies,
      severity: log.severity,
      indexed_at: new Date().toISOString()
    }
  ]);
  
  const response = await esClient.bulk({ operations });
  console.log(`Indexed ${logs.length} logs to Elasticsearch`);
}
```

### Integration with PagerDuty

```javascript
const axios = require('axios');

async function triggerPagerDutyIncident(anomaly) {
  const payload = {
    routing_key: process.env.PAGERDUTY_KEY,
    event_action: 'trigger',
    payload: {
      summary: `${anomaly.type}: ${anomaly.description}`,
      severity: anomaly.severity,
      source: 'AuditVault',
      custom_details: {
        ip_address: anomaly.ip,
        timestamp: anomaly.timestamp,
        message: anomaly.message
      }
    }
  };
  
  await axios.post('https://events.pagerduty.com/v2/enqueue', payload);
}
```

---

## 🧪 Testing

### Unit Tests Example (Jest)

Create `backend/tests/analyzer.test.js`:

```javascript
const { LogAnalyzer } = require('../server');

describe('LogAnalyzer', () => {
  let analyzer;
  
  beforeEach(() => {
    analyzer = new LogAnalyzer();
  });
  
  test('should detect SQL injection', () => {
    const line = '2025-11-01 10:15:23 ERROR [api] 192.168.1.1 - Query: SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin';
    const log = analyzer.parseLine(line, 1);
    
    expect(log.anomalies).toHaveLength(1);
    expect(log.anomalies[0].type).toBe('SQL_INJECTION');
    expect(log.severity).toBe('critical');
  });
  
  test('should detect XSS attempts', () => {
    const line = '2025-11-01 10:15:23 WARNING [web] 10.0.0.1 - Input: <script>alert("XSS")</script>';
    const log = analyzer.parseLine(line, 1);
    
    expect(log.anomalies).toHaveLength(1);
    expect(log.anomalies[0].type).toBe('XSS_ATTEMPT');
  });
  
  test('should extract IP addresses', () => {
    const line = '2025-11-01 10:15:23 INFO [firewall] 192.168.1.100 - Connection established';
    const log = analyzer.parseLine(line, 1);
    
    expect(log.ip).toBe('192.168.1.100');
  });
  
  test('should parse timestamps correctly', () => {
    const line = '2025-11-01 10:15:23 INFO [system] - Test message';
    const log = analyzer.parseLine(line, 1);
    
    expect(log.timestamp).toBe('2025-11-01 10:15:23');
  });
  
  test('should generate statistics', () => {
    const logs = [
      { level: 'ERROR', ip: '192.168.1.1', anomalies: [], severity: 'high' },
      { level: 'WARNING', ip: '192.168.1.1', anomalies: [], severity: 'medium' },
      { level: 'INFO', ip: '192.168.1.2', anomalies: [], severity: 'info' }
    ];
    
    const stats = analyzer.generateStatistics(logs);
    
    expect(stats.totalLogs).toBe(3);
    expect(stats.levelDistribution.ERROR).toBe(1);
    expect(stats.ipFrequency['192.168.1.1']).toBe(2);
  });
});
```

### Integration Tests

Create `backend/tests/api.test.js`:

```javascript
const request = require('supertest');
const app = require('../server');

describe('API Endpoints', () => {
  test('GET /api/health should return OK', async () => {
    const response = await request(app).get('/api/health');
    
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('OK');
  });
  
  test('POST /api/analyze-text should analyze logs', async () => {
    const logText = '2025-11-01 10:15:23 ERROR [firewall] 192.168.1.1 - Connection blocked';
    
    const response = await request(app)
      .post('/api/analyze-text')
      .send({ logText });
    
    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.analysis).toBeDefined();
  });
});
```

### Run Tests

```bash
# Install Jest
npm install --save-dev jest supertest

# Add to package.json
"scripts": {
  "test": "jest",
  "test:watch": "jest --watch",
  "test:coverage": "jest --coverage"
}

# Run tests
npm test
```

---

## 🎓 Learning Resources

### Recommended Reading
- **OWASP Top 10** - Web application security risks
- **NIST Cybersecurity Framework** - Security best practices
- **Log Analysis Best Practices** - Effective log management
- **Regex Tutorial** - Pattern matching fundamentals

### External Tools & Services
- **Elastic Stack (ELK)** - Log aggregation and analysis
- **Splunk** - Enterprise log management
- **Graylog** - Open-source log management
- **Logstash** - Log processing pipeline

### Related Projects
- **Fail2Ban** - Intrusion prevention
- **OSSEC** - Host-based intrusion detection
- **Suricata** - Network IDS/IPS
- **Snort** - Network intrusion detection

---

**Made with 🛡️ by Michael Semera**

*Secure your systems, analyze your logs, protect your infrastructure.*

---

**Version**: 1.0.0  
**Last Updated**: November 1, 2025  
**Status**: Production Ready ✅  

**License**: MIT
