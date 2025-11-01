// server.js - AuditVault Backend by Michael Semera
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const multer = require('multer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// File upload configuration
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /log|txt|csv/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    if (extname) {
      return cb(null, true);
    }
    cb(new Error('Only .log, .txt, and .csv files are allowed'));
  }
});

// Log Analysis Engine
class LogAnalyzer {
  constructor() {
    this.patterns = {
      timestamp: /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/,
      ip: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/,
      level: /\b(INFO|WARNING|ERROR|CRITICAL|DEBUG|FATAL)\b/i,
      httpStatus: /\b(2\d{2}|3\d{2}|4\d{2}|5\d{2})\b/,
      sqlInjection: /(union\s+select|drop\s+table|insert\s+into|delete\s+from|exec\s*\()/i,
      xss: /(<script|javascript:|onerror=|onload=)/i,
      bruteForce: /failed.*login|authentication.*failed|invalid.*credentials/i,
      portScan: /port\s*scan|scanning.*port|nmap/i
    };

    this.anomalyThresholds = {
      failedLoginAttempts: 3,
      requestsPerMinute: 100,
      uniqueIPsPerMinute: 50,
      errorRate: 0.1
    };
  }

  parseLine(line, lineNumber) {
    const log = {
      lineNumber,
      raw: line,
      timestamp: null,
      level: 'INFO',
      ip: null,
      message: line,
      anomalies: [],
      severity: 'info'
    };

    // Extract timestamp
    const timestampMatch = line.match(this.patterns.timestamp);
    if (timestampMatch) {
      log.timestamp = timestampMatch[1];
    }

    // Extract log level
    const levelMatch = line.match(this.patterns.level);
    if (levelMatch) {
      log.level = levelMatch[1].toUpperCase();
    }

    // Extract IP address
    const ipMatch = line.match(this.patterns.ip);
    if (ipMatch) {
      log.ip = ipMatch[1];
    }

    // Detect anomalies
    this.detectAnomalies(log);

    // Calculate severity
    log.severity = this.calculateSeverity(log);

    return log;
  }

  detectAnomalies(log) {
    const message = log.message.toLowerCase();

    if (this.patterns.sqlInjection.test(message)) {
      log.anomalies.push({
        type: 'SQL_INJECTION',
        description: 'Potential SQL injection attempt detected',
        severity: 'critical'
      });
    }

    if (this.patterns.xss.test(message)) {
      log.anomalies.push({
        type: 'XSS_ATTEMPT',
        description: 'Potential XSS attack detected',
        severity: 'critical'
      });
    }

    if (this.patterns.bruteForce.test(message)) {
      log.anomalies.push({
        type: 'BRUTE_FORCE',
        description: 'Possible brute force attack',
        severity: 'high'
      });
    }

    if (this.patterns.portScan.test(message)) {
      log.anomalies.push({
        type: 'PORT_SCAN',
        description: 'Port scanning activity detected',
        severity: 'high'
      });
    }

    if (log.level === 'ERROR' || log.level === 'CRITICAL' || log.level === 'FATAL') {
      log.anomalies.push({
        type: 'ERROR_LOG',
        description: `${log.level} level log entry`,
        severity: log.level === 'CRITICAL' || log.level === 'FATAL' ? 'critical' : 'high'
      });
    }
  }

  calculateSeverity(log) {
    if (log.anomalies.some(a => a.severity === 'critical')) return 'critical';
    if (log.anomalies.some(a => a.severity === 'high')) return 'high';
    if (log.level === 'WARNING') return 'medium';
    if (log.level === 'ERROR') return 'high';
    if (log.level === 'CRITICAL') return 'critical';
    return 'info';
  }

  async analyzeFile(filePath) {
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n').filter(line => line.trim());
    
    const logs = lines.map((line, index) => this.parseLine(line, index + 1));
    
    const analysis = this.generateStatistics(logs);
    
    return { logs, analysis };
  }

  generateStatistics(logs) {
    const stats = {
      totalLogs: logs.length,
      levelDistribution: {},
      ipFrequency: {},
      anomalyTypes: {},
      timeline: {},
      severityCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      topAnomalies: [],
      suspiciousIPs: []
    };

    logs.forEach(log => {
      // Level distribution
      stats.levelDistribution[log.level] = (stats.levelDistribution[log.level] || 0) + 1;

      // IP frequency
      if (log.ip) {
        stats.ipFrequency[log.ip] = (stats.ipFrequency[log.ip] || 0) + 1;
      }

      // Severity count
      stats.severityCount[log.severity]++;

      // Anomaly types
      log.anomalies.forEach(anomaly => {
        stats.anomalyTypes[anomaly.type] = (stats.anomalyTypes[anomaly.type] || 0) + 1;
      });

      // Timeline
      if (log.timestamp) {
        const hour = log.timestamp.split(' ')[1]?.split(':')[0] || '00';
        stats.timeline[hour] = (stats.timeline[hour] || 0) + 1;
      }
    });

    // Find suspicious IPs (multiple failed attempts)
    Object.entries(stats.ipFrequency).forEach(([ip, count]) => {
      if (count > 5) {
        const ipLogs = logs.filter(l => l.ip === ip);
        const anomalyCount = ipLogs.reduce((acc, l) => acc + l.anomalies.length, 0);
        if (anomalyCount > 0) {
          stats.suspiciousIPs.push({ ip, count, anomalyCount });
        }
      }
    });

    // Sort suspicious IPs
    stats.suspiciousIPs.sort((a, b) => b.anomalyCount - a.anomalyCount);

    // Get top anomalies
    stats.topAnomalies = logs
      .filter(l => l.anomalies.length > 0)
      .slice(0, 20);

    return stats;
  }

  generateReport(analysis, logs) {
    const report = {
      metadata: {
        generatedAt: new Date().toISOString(),
        tool: 'AuditVault',
        author: 'Michael Semera',
        version: '1.0.0'
      },
      summary: {
        totalLogs: analysis.totalLogs,
        criticalIssues: analysis.severityCount.critical,
        highSeverity: analysis.severityCount.high,
        mediumSeverity: analysis.severityCount.medium,
        anomaliesDetected: analysis.topAnomalies.length
      },
      statistics: analysis,
      criticalLogs: logs.filter(l => l.severity === 'critical'),
      recommendations: this.generateRecommendations(analysis)
    };

    return report;
  }

  generateRecommendations(analysis) {
    const recommendations = [];

    if (analysis.severityCount.critical > 0) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Security',
        issue: `${analysis.severityCount.critical} critical security issues detected`,
        action: 'Immediate investigation required. Review all critical logs and block suspicious IPs.'
      });
    }

    if (analysis.anomalyTypes.SQL_INJECTION > 0) {
      recommendations.push({
        priority: 'CRITICAL',
        category: 'Security',
        issue: 'SQL injection attempts detected',
        action: 'Review database access logs, implement parameterized queries, and update WAF rules.'
      });
    }

    if (analysis.anomalyTypes.BRUTE_FORCE > 0) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Authentication',
        issue: 'Brute force attacks detected',
        action: 'Implement rate limiting, CAPTCHA, and account lockout mechanisms.'
      });
    }

    if (analysis.suspiciousIPs.length > 0) {
      recommendations.push({
        priority: 'MEDIUM',
        category: 'Network',
        issue: `${analysis.suspiciousIPs.length} suspicious IP addresses identified`,
        action: 'Consider blocking or rate-limiting these IPs at the firewall level.'
      });
    }

    const errorRate = (analysis.levelDistribution.ERROR || 0) / analysis.totalLogs;
    if (errorRate > 0.1) {
      recommendations.push({
        priority: 'MEDIUM',
        category: 'System Health',
        issue: `High error rate detected (${(errorRate * 100).toFixed(2)}%)`,
        action: 'Investigate system stability and review error logs for patterns.'
      });
    }

    return recommendations;
  }
}

const analyzer = new LogAnalyzer();

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'AuditVault API is running',
    version: '1.0.0',
    author: 'Michael Semera'
  });
});

// Upload and analyze log file
app.post('/api/analyze', upload.single('logFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const result = await analyzer.analyzeFile(req.file.path);
    const report = analyzer.generateReport(result.analysis, result.logs);

    // Clean up uploaded file
    await fs.unlink(req.file.path);

    res.json({
      success: true,
      report,
      logs: result.logs,
      analysis: result.analysis
    });
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Failed to analyze log file' });
  }
});

// Analyze log text directly
app.post('/api/analyze-text', async (req, res) => {
  try {
    const { logText } = req.body;

    if (!logText) {
      return res.status(400).json({ error: 'No log text provided' });
    }

    const tempFile = path.join(__dirname, 'temp', `log-${Date.now()}.txt`);
    await fs.mkdir(path.dirname(tempFile), { recursive: true });
    await fs.writeFile(tempFile, logText);

    const result = await analyzer.analyzeFile(tempFile);
    const report = analyzer.generateReport(result.analysis, result.logs);

    await fs.unlink(tempFile);

    res.json({
      success: true,
      report,
      logs: result.logs,
      analysis: result.analysis
    });
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Failed to analyze log text' });
  }
});

// Get sample logs for testing
app.get('/api/sample-logs', (req, res) => {
  const sampleLogs = `2025-11-01 10:15:23 ERROR [firewall] 192.168.1.105 - Blocked suspicious connection attempt from external IP
2025-11-01 10:16:45 WARNING [auth] 10.0.0.15 - Failed login attempt for user admin
2025-11-01 10:17:02 INFO [system] 10.0.0.1 - System backup completed successfully
2025-11-01 10:18:33 CRITICAL [security] 203.0.113.45 - SQL injection attempt: SELECT * FROM users WHERE id=1 UNION SELECT * FROM passwords
2025-11-01 10:19:12 WARNING [auth] 10.0.0.15 - Failed login attempt for user admin
2025-11-01 10:20:56 ERROR [database] 10.0.0.50 - Connection pool exhausted
2025-11-01 10:21:44 INFO [api] 10.0.0.100 - GET /api/users 200 45ms
2025-11-01 10:22:17 WARNING [auth] 10.0.0.15 - Failed login attempt for user admin
2025-11-01 10:23:05 CRITICAL [security] 198.51.100.23 - XSS attempt detected: <script>alert('XSS')</script>
2025-11-01 10:24:38 ERROR [firewall] 203.0.113.45 - Port scan detected from external IP`;

  res.json({ logs: sampleLogs });
});

// Export report as JSON
app.post('/api/export', async (req, res) => {
  try {
    const { report } = req.body;
    
    if (!report) {
      return res.status(400).json({ error: 'No report data provided' });
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=audit-report-${Date.now()}.json`);
    res.json(report);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Failed to export report' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`AuditVault server running on port ${PORT}`);
  console.log(`Created by Michael Semera`);
  console.log(`API available at http://localhost:${PORT}/api`);
});