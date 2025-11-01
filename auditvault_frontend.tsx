import React, { useState, useEffect } from 'react';
import { Shield, Upload, AlertTriangle, CheckCircle, XCircle, FileText, Download, Search, Filter, TrendingUp, Activity, Lock, Globe, Server } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const AuditVault = () => {
  const [logs, setLogs] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [filters, setFilters] = useState({ level: 'all', search: '' });
  const [activeTab, setActiveTab] = useState('overview');

  const COLORS = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6'];
  const SEVERITY_COLORS = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#f59e0b',
    low: '#84cc16',
    info: '#22c55e'
  };

  useEffect(() => {
    loadSampleLogs();
  }, []);

  const loadSampleLogs = () => {
    const sampleLogs = [
      { timestamp: '2025-11-01 10:15:23', level: 'ERROR', source: 'firewall', ip: '192.168.1.105', message: 'Blocked suspicious connection attempt from external IP', severity: 'high' },
      { timestamp: '2025-11-01 10:16:45', level: 'WARNING', source: 'auth', ip: '10.0.0.15', message: 'Failed login attempt for user admin', severity: 'medium' },
      { timestamp: '2025-11-01 10:17:02', level: 'INFO', source: 'system', ip: '10.0.0.1', message: 'System backup completed successfully', severity: 'info' },
      { timestamp: '2025-11-01 10:18:33', level: 'ERROR', source: 'firewall', ip: '203.0.113.45', message: 'Port scan detected from external IP', severity: 'critical' },
      { timestamp: '2025-11-01 10:19:12', level: 'WARNING', source: 'auth', ip: '10.0.0.15', message: 'Failed login attempt for user admin', severity: 'medium' },
      { timestamp: '2025-11-01 10:20:56', level: 'ERROR', source: 'database', ip: '10.0.0.50', message: 'Connection pool exhausted', severity: 'high' },
      { timestamp: '2025-11-01 10:21:44', level: 'INFO', source: 'api', ip: '10.0.0.100', message: 'API request processed in 45ms', severity: 'info' },
      { timestamp: '2025-11-01 10:22:17', level: 'WARNING', source: 'auth', ip: '10.0.0.15', message: 'Failed login attempt for user admin', severity: 'medium' },
      { timestamp: '2025-11-01 10:23:05', level: 'CRITICAL', source: 'security', ip: '198.51.100.23', message: 'SQL injection attempt detected', severity: 'critical' },
      { timestamp: '2025-11-01 10:24:38', level: 'ERROR', source: 'firewall', ip: '203.0.113.45', message: 'Multiple connection attempts blocked', severity: 'high' }
    ];
    setLogs(sampleLogs);
    analyzeLogs(sampleLogs);
  };

  const analyzeLogs = (logData) => {
    const levelCounts = {};
    const sourceCounts = {};
    const ipFrequency = {};
    const anomalies = [];
    const timeline = {};

    logData.forEach(log => {
      levelCounts[log.level] = (levelCounts[log.level] || 0) + 1;
      sourceCounts[log.source] = (sourceCounts[log.source] || 0) + 1;
      ipFrequency[log.ip] = (ipFrequency[log.ip] || 0) + 1;
      
      const hour = log.timestamp.split(' ')[1].split(':')[0];
      timeline[hour] = (timeline[hour] || 0) + 1;

      if (log.level === 'ERROR' || log.level === 'CRITICAL') {
        anomalies.push(log);
      }
      
      if (ipFrequency[log.ip] > 2) {
        const exists = anomalies.find(a => a.ip === log.ip && a.type === 'repeated_access');
        if (!exists) {
          anomalies.push({
            ...log,
            type: 'repeated_access',
            message: `Suspicious: ${log.ip} accessed ${ipFrequency[log.ip]} times`
          });
        }
      }
    });

    const levelData = Object.entries(levelCounts).map(([name, value]) => ({ name, value }));
    const sourceData = Object.entries(sourceCounts).map(([name, value]) => ({ name, value }));
    const timelineData = Object.entries(timeline).map(([hour, count]) => ({ hour: `${hour}:00`, count }));

    setAnalysis({
      totalLogs: logData.length,
      levelData,
      sourceData,
      timelineData,
      anomalies,
      criticalCount: anomalies.length,
      topIPs: Object.entries(ipFrequency)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count }))
    });
  };

  const parseLogFile = (text) => {
    const lines = text.split('\n').filter(line => line.trim());
    const parsed = lines.map((line, index) => {
      const timestampMatch = line.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
      const levelMatch = line.match(/\b(INFO|WARNING|ERROR|CRITICAL|DEBUG)\b/i);
      const ipMatch = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
      
      return {
        timestamp: timestampMatch ? timestampMatch[1] : new Date().toISOString().slice(0, 19).replace('T', ' '),
        level: levelMatch ? levelMatch[1].toUpperCase() : 'INFO',
        source: 'imported',
        ip: ipMatch ? ipMatch[1] : '0.0.0.0',
        message: line,
        severity: levelMatch && ['ERROR', 'CRITICAL'].includes(levelMatch[1].toUpperCase()) ? 'high' : 'low'
      };
    });
    
    setLogs(parsed);
    analyzeLogs(parsed);
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => parseLogFile(event.target.result);
      reader.readAsText(file);
    }
  };

  const exportToJSON = () => {
    const report = {
      generated: new Date().toISOString(),
      summary: analysis,
      logs: logs,
      author: 'Michael Semera',
      tool: 'AuditVault'
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-report-${Date.now()}.json`;
    a.click();
  };

  const filteredLogs = logs.filter(log => {
    const levelMatch = filters.level === 'all' || log.level === filters.level;
    const searchMatch = !filters.search || 
      log.message.toLowerCase().includes(filters.search.toLowerCase()) ||
      log.ip.includes(filters.search);
    return levelMatch && searchMatch;
  });

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <div className="container mx-auto px-4 py-8">
        <header className="mb-8 text-center">
          <div className="flex items-center justify-center gap-3 mb-2">
            <Shield className="text-blue-400" size={48} />
            <h1 className="text-5xl font-bold text-white">AuditVault</h1>
          </div>
          <p className="text-blue-200 text-lg">Forensic Log Analyzer & Anomaly Detection</p>
          <p className="text-blue-300 text-sm mt-1">by Michael Semera</p>
        </header>

        <div className="mb-6 flex flex-wrap gap-4">
          <label className="flex-1 min-w-[200px] bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-xl font-semibold cursor-pointer transition-all flex items-center justify-center gap-2">
            <Upload size={20} />
            Upload Log File
            <input type="file" accept=".log,.txt" onChange={handleFileUpload} className="hidden" />
          </label>
          
          <button
            onClick={exportToJSON}
            className="flex-1 min-w-[200px] bg-green-600 hover:bg-green-700 text-white px-6 py-3 rounded-xl font-semibold transition-all flex items-center justify-center gap-2"
          >
            <Download size={20} />
            Export Report (JSON)
          </button>
        </div>

        {analysis && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
              <div className="bg-gradient-to-br from-blue-600 to-blue-700 rounded-2xl p-6 text-white">
                <div className="flex items-center justify-between mb-2">
                  <FileText size={32} />
                  <span className="text-3xl font-bold">{analysis.totalLogs}</span>
                </div>
                <p className="text-blue-100 font-medium">Total Logs</p>
              </div>

              <div className="bg-gradient-to-br from-red-600 to-red-700 rounded-2xl p-6 text-white">
                <div className="flex items-center justify-between mb-2">
                  <AlertTriangle size={32} />
                  <span className="text-3xl font-bold">{analysis.criticalCount}</span>
                </div>
                <p className="text-red-100 font-medium">Anomalies Detected</p>
              </div>

              <div className="bg-gradient-to-br from-purple-600 to-purple-700 rounded-2xl p-6 text-white">
                <div className="flex items-center justify-between mb-2">
                  <Server size={32} />
                  <span className="text-3xl font-bold">{analysis.sourceData.length}</span>
                </div>
                <p className="text-purple-100 font-medium">Log Sources</p>
              </div>

              <div className="bg-gradient-to-br from-green-600 to-green-700 rounded-2xl p-6 text-white">
                <div className="flex items-center justify-between mb-2">
                  <Activity size={32} />
                  <span className="text-3xl font-bold">{analysis.topIPs.length}</span>
                </div>
                <p className="text-green-100 font-medium">Unique IPs</p>
              </div>
            </div>

            <div className="mb-6 flex gap-2 bg-slate-800 rounded-xl p-1">
              {['overview', 'anomalies', 'logs'].map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`flex-1 py-3 px-4 rounded-lg font-medium transition-all ${
                    activeTab === tab
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>

            {activeTab === 'overview' && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-slate-800 rounded-2xl p-6">
                  <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                    <TrendingUp className="text-blue-400" />
                    Log Levels Distribution
                  </h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={analysis.levelData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {analysis.levelData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                <div className="bg-slate-800 rounded-2xl p-6">
                  <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                    <Server className="text-purple-400" />
                    Sources
                  </h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={analysis.sourceData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="name" stroke="#9ca3af" />
                      <YAxis stroke="#9ca3af" />
                      <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none' }} />
                      <Bar dataKey="value" fill="#8b5cf6" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="bg-slate-800 rounded-2xl p-6 lg:col-span-2">
                  <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                    <Activity className="text-green-400" />
                    Timeline Activity
                  </h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={analysis.timelineData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="hour" stroke="#9ca3af" />
                      <YAxis stroke="#9ca3af" />
                      <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none' }} />
                      <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>

                <div className="bg-slate-800 rounded-2xl p-6 lg:col-span-2">
                  <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                    <Globe className="text-cyan-400" />
                    Top Active IP Addresses
                  </h3>
                  <div className="space-y-3">
                    {analysis.topIPs.map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between bg-slate-700 rounded-xl p-4">
                        <span className="text-white font-mono">{item.ip}</span>
                        <div className="flex items-center gap-3">
                          <div className="bg-slate-600 rounded-full h-2 w-48">
                            <div
                              className="bg-blue-500 h-2 rounded-full"
                              style={{ width: `${(item.count / Math.max(...analysis.topIPs.map(i => i.count))) * 100}%` }}
                            />
                          </div>
                          <span className="text-blue-300 font-bold">{item.count}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'anomalies' && (
              <div className="bg-slate-800 rounded-2xl p-6">
                <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                  <AlertTriangle className="text-red-400" />
                  Detected Anomalies ({analysis.anomalies.length})
                </h3>
                <div className="space-y-3">
                  {analysis.anomalies.map((anomaly, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-700 rounded-xl p-4 border-l-4"
                      style={{ borderColor: SEVERITY_COLORS[anomaly.severity] }}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <AlertTriangle size={20} className="text-red-400" />
                          <span className="text-white font-bold">{anomaly.level}</span>
                          <span className="text-slate-400 text-sm">{anomaly.timestamp}</span>
                        </div>
                        <span
                          className="px-3 py-1 rounded-full text-xs font-bold text-white"
                          style={{ backgroundColor: SEVERITY_COLORS[anomaly.severity] }}
                        >
                          {anomaly.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-slate-300 mb-2">{anomaly.message}</p>
                      <div className="flex gap-4 text-sm">
                        <span className="text-slate-400">Source: <span className="text-blue-400">{anomaly.source}</span></span>
                        <span className="text-slate-400">IP: <span className="text-cyan-400 font-mono">{anomaly.ip}</span></span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'logs' && (
              <div className="bg-slate-800 rounded-2xl p-6">
                <div className="mb-4 flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 text-slate-400" size={20} />
                    <input
                      type="text"
                      placeholder="Search logs..."
                      value={filters.search}
                      onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                      className="w-full bg-slate-700 text-white pl-10 pr-4 py-3 rounded-xl border border-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <select
                    value={filters.level}
                    onChange={(e) => setFilters({ ...filters, level: e.target.value })}
                    className="bg-slate-700 text-white px-4 py-3 rounded-xl border border-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="all">All Levels</option>
                    <option value="INFO">INFO</option>
                    <option value="WARNING">WARNING</option>
                    <option value="ERROR">ERROR</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>

                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {filteredLogs.map((log, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-700 rounded-lg p-3 hover:bg-slate-600 transition-colors"
                    >
                      <div className="flex items-center gap-3 mb-1">
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          log.level === 'ERROR' || log.level === 'CRITICAL' ? 'bg-red-600 text-white' :
                          log.level === 'WARNING' ? 'bg-yellow-600 text-white' :
                          'bg-green-600 text-white'
                        }`}>
                          {log.level}
                        </span>
                        <span className="text-slate-400 text-sm">{log.timestamp}</span>
                        <span className="text-blue-400 text-sm">{log.source}</span>
                        <span className="text-cyan-400 text-sm font-mono">{log.ip}</span>
                      </div>
                      <p className="text-slate-200 text-sm">{log.message}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default AuditVault;