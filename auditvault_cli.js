#!/usr/bin/env node
// cli.js - AuditVault Command Line Interface by Michael Semera

const fs = require('fs').promises;
const path = require('path');
const readline = require('readline');

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

class AuditVaultCLI {
  constructor() {
    this.patterns = {
      timestamp: /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/,
      ip: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/,
      level: /\b(INFO|WARNING|ERROR|CRITICAL|DEBUG|FATAL)\b/i,
      sqlInjection: /(union\s+select|drop\s+table|insert\s+into|delete\s+from|exec\s*\()/i,
      xss: /(<script|javascript:|onerror=|onload=)/i,
      bruteForce: /failed.*login|authentication.*failed|invalid.*credentials/i,
      portScan: /port\s*scan|scanning.*port|nmap/i
    };
  }

  async run(args) {
    const command = args[2];
    const filePath = args[3];

    this.printBanner();

    if (!command) {
      this.printUsage();
      return;
    }

    switch (command) {
      case 'analyze':
        if (!filePath) {
          console.log(`${colors.red}Error: Please provide a log file path${colors.reset}`);
          this.printUsage();
          return;
        }
        await this.analyze(filePath);
        break;

      case 'watch':
        if (!filePath) {
          console.log(`${colors.red}Error: Please provide a log file path${colors.reset}`);
          this.printUsage();
          return;
        }
        await this.watch(filePath);
        break;

      case 'export':
        if (!filePath || !args[4]) {
          console.log(`${colors.red}Error: Please provide input and output file paths${colors.reset}`);
          console.log(`Usage: auditvault export <input.log> <output.json>`);
          return;
        }
        await this.export(filePath, args[4]);
        break;

      case 'help':
        this.printUsage();
        break;

      default:
        console.log(`${colors.red}Unknown command: ${command}${colors.reset}`);
        this.printUsage();
    }
  }

  printBanner() {
    console.log(`${colors.cyan}${colors.bright}`);
    console.log(`
╔═══════════════════════════════════════════╗
║           🛡️  AuditVault CLI             ║
║    Forensic Log Analyzer & Detector      ║
║         by Michael Semera                ║
╚═══════════════════════════════════════════╝
    `);
    console.log(colors.reset);
  }

  printUsage() {
    console.log(`${colors.yellow}Usage:${colors.reset}`);
    console.log(`  auditvault <command> [options]\n`);
    console.log(`${colors.yellow}Commands:${colors.reset}`);
    console.log(`  ${colors.green}analyze${colors.reset} <file>        Analyze a log file and display results`);
    console.log(`  ${colors.green}watch${colors.reset} <file>          Watch a log file for real-time analysis`);
    console.log(`  ${colors.green}export${colors.reset} <in> <out>     Analyze and export results to JSON`);
    console.log(`  ${colors.green}help${colors.reset}                  Show this help message\n`);
    console.log(`${colors.yellow}Examples:${colors.reset}`);
    console.log(`  auditvault analyze /var/log/system.log`);
    console.log(`  auditvault watch /var/log/auth.log`);
    console.log(`  auditvault export system.log report.json\n`);
  }

  async analyze(filePath) {
    try {
      console.log(`${colors.blue}Analyzing: ${filePath}${colors.reset}\n`);

      const content = await fs.readFile(filePath, 'utf-8');
      const lines = content.split('\n').filter(line => line.trim());

      const logs = lines.map((line, index) => this.parseLine(line, index + 1));
      const analysis = this.generateStatistics(logs);

      this.printResults(analysis, logs);
    } catch (error) {
      console.error(`${colors.red}Error: ${error.message}${colors.reset}`);
    }
  }

  async watch(filePath) {
    console.log(`${colors.blue}Watching: ${filePath}${colors.reset}`);
    console.log(`${colors.yellow}Press Ctrl+C to stop${colors.reset}\n`);

    let lastSize = 0;

    const checkFile = async () => {
      try {
        const stats = await fs.stat(filePath);
        
        if (stats.size > lastSize) {
          const content = await fs.readFile(filePath, 'utf-8');
          const newContent = content.slice(lastSize);
          const lines = newContent.split('\n').filter(line => line.trim());

          lines.forEach(line => {
            const log = this.parseLine(line, 0);
            if (log.anomalies.length > 0) {
              this.printAlert(log);
            }
          });

          lastSize = stats.size;
        }
      } catch (error) {
        if (error.code !== 'ENOENT') {
          console.error(`${colors.red}Error: ${error.message}${colors.reset}`);
        }
      }
    };

    // Check every second
    const interval = setInterval(checkFile, 1000);

    // Handle Ctrl+C
    process.on('SIGINT', () => {
      clearInterval(interval);
      console.log(`\n${colors.yellow}Stopped watching${colors.reset}`);
      process.exit(0);
    });
  }

  async export(inputPath, outputPath) {
    try {
      console.log(`${colors.blue}Analyzing: ${inputPath}${colors.reset}`);

      const content = await fs.readFile(inputPath, 'utf-8');
      const lines = content.split('\n').filter(line => line.trim());

      const logs = lines.map((line, index) => this.parseLine(line, index + 1));
      const analysis = this.generateStatistics(logs);

      const report = {
        metadata: {
          generatedAt: new Date().toISOString(),
          tool: 'AuditVault CLI',
          author: 'Michael Semera',
          version: '1.0.0',
          sourceFile: inputPath
        },
        summary: {
          totalLogs: analysis.totalLogs,
          criticalIssues: analysis.severityCount.critical,
          highSeverity: analysis.severityCount.high,
          anomaliesDetected: analysis.topAnomalies.length
        },
        statistics: analysis,
        criticalLogs: logs.filter(l => l.severity === 'critical'),
        recommendations: this.generateRecommendations(analysis)
      };

      await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
      console.log(`${colors.green}✓ Report exported to: ${outputPath}${colors.reset}`);
    } catch (error) {
      console.error(`${colors.red}Error: ${error.message}${colors.reset}`);
    }
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

    const timestampMatch = line.match(this.patterns.timestamp);
    if (timestampMatch) log.timestamp = timestampMatch[1];

    const levelMatch = line.match(this.patterns.level);
    if (levelMatch) log.level = levelMatch[1].toUpperCase();

    const ipMatch = line.match(this.patterns.ip);
    if (ipMatch) log.ip = ipMatch[1];

    this.detectAnomalies(log);
    log.severity = this.calculateSeverity(log);

    return log;
  }

  detectAnomalies(log) {
    const message = log.message.toLowerCase();

    if (this.patterns.sqlInjection.test(message)) {
      log.anomalies.push({
        type: 'SQL_INJECTION',
        description: 'Potential SQL injection attempt',
        severity: 'critical'
      });
    }

    if (this.patterns.xss.test(message)) {
      log.anomalies.push({
        type: 'XSS_ATTEMPT',
        description: 'Potential XSS attack',
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
        description: 'Port scanning detected',
        severity: 'high'
      });
    }

    if (['ERROR', 'CRITICAL', 'FATAL'].includes(log.level)) {
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

  generateStatistics(logs) {
    const stats = {
      totalLogs: logs.length,
      levelDistribution: {},
      ipFrequency: {},
      anomalyTypes: {},
      severityCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      topAnomalies: [],
      suspiciousIPs: []
    };

    logs.forEach(log => {
      stats.levelDistribution[log.level] = (stats.levelDistribution[log.level] || 0) + 1;
      if (log.ip) stats.ipFrequency[log.ip] = (stats.ipFrequency[log.ip] || 0) + 1;
      stats.severityCount[log.severity]++;
      log.anomalies.forEach(anomaly => {
        stats.anomalyTypes[anomaly.type] = (stats.anomalyTypes[anomaly.type] || 0) + 1;
      });
    });

    Object.entries(stats.ipFrequency).forEach(([ip, count]) => {
      if (count > 5) {
        const ipLogs = logs.filter(l => l.ip === ip);
        const anomalyCount = ipLogs.reduce((acc, l) => acc + l.anomalies.length, 0);
        if (anomalyCount > 0) {
          stats.suspiciousIPs.push({ ip, count, anomalyCount });
        }
      }
    });

    stats.suspiciousIPs.sort((a, b) => b.anomalyCount - a.anomalyCount);
    stats.topAnomalies = logs.filter(l => l.anomalies.length > 0);

    return stats;
  }

  generateRecommendations(analysis) {
    const recommendations = [];

    if (analysis.severityCount.critical > 0) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Security',
        issue: `${analysis.severityCount.critical} critical issues detected`,
        action: 'Immediate investigation required'
      });
    }

    if (analysis.anomalyTypes.SQL_INJECTION > 0) {
      recommendations.push({
        priority: 'CRITICAL',
        category: 'Security',
        issue: 'SQL injection attempts detected',
        action: 'Review database access and implement parameterized queries'
      });
    }

    return recommendations;
  }

  printResults(analysis, logs) {
    console.log(`${colors.bright}═══════════════════════════════════════════${colors.reset}\n`);
    
    // Summary
    console.log(`${colors.cyan}${colors.bright}SUMMARY${colors.reset}`);
    console.log(`  Total Logs:      ${colors.green}${analysis.totalLogs}${colors.reset}`);
    console.log(`  Critical Issues: ${colors.red}${analysis.severityCount.critical}${colors.reset}`);
    console.log(`  High Severity:   ${colors.yellow}${analysis.severityCount.high}${colors.reset}`);
    console.log(`  Medium Severity: ${colors.blue}${analysis.severityCount.medium}${colors.reset}\n`);

    // Level Distribution
    if (Object.keys(analysis.levelDistribution).length > 0) {
      console.log(`${colors.cyan}${colors.bright}LEVEL DISTRIBUTION${colors.reset}`);
      Object.entries(analysis.levelDistribution).forEach(([level, count]) => {
        const color = level === 'ERROR' || level === 'CRITICAL' ? colors.red :
                     level === 'WARNING' ? colors.yellow : colors.green;
        console.log(`  ${color}${level.padEnd(10)}${colors.reset} ${'█'.repeat(Math.min(count, 50))} ${count}`);
      });
      console.log();
    }

    // Suspicious IPs
    if (analysis.suspiciousIPs.length > 0) {
      console.log(`${colors.cyan}${colors.bright}SUSPICIOUS IPs${colors.reset}`);
      analysis.suspiciousIPs.slice(0, 5).forEach(item => {
        console.log(`  ${colors.red}${item.ip}${colors.reset} - ${item.count} requests, ${item.anomalyCount} anomalies`);
      });
      console.log();
    }

    // Top Anomalies
    if (analysis.topAnomalies.length > 0) {
      console.log(`${colors.cyan}${colors.bright}TOP ANOMALIES${colors.reset}`);
      analysis.topAnomalies.slice(0, 10).forEach(log => {
        const severityColor = log.severity === 'critical' ? colors.red :
                             log.severity === 'high' ? colors.yellow : colors.blue;
        console.log(`  ${severityColor}[${log.severity.toUpperCase()}]${colors.reset} Line ${log.lineNumber}`);
        console.log(`    ${log.message.slice(0, 80)}...`);
        log.anomalies.forEach(anomaly => {
          console.log(`    → ${colors.magenta}${anomaly.type}${colors.reset}: ${anomaly.description}`);
        });
        console.log();
      });
    }

    console.log(`${colors.bright}═══════════════════════════════════════════${colors.reset}\n`);
  }

  printAlert(log) {
    const timestamp = new Date().toISOString();
    console.log(`${colors.red}[ALERT]${colors.reset} ${timestamp}`);
    console.log(`  Level: ${log.level}`);
    console.log(`  IP: ${log.ip || 'N/A'}`);
    console.log(`  Message: ${log.message.slice(0, 100)}`);
    log.anomalies.forEach(anomaly => {
      console.log(`  → ${colors.yellow}${anomaly.type}${colors.reset}: ${anomaly.description}`);
    });
    console.log();
  }
}

// Run CLI
const cli = new AuditVaultCLI();
cli.run(process.argv);