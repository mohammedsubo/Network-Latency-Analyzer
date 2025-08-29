# 🌐 Network Latency Analyzer v1.1

Professional network performance analysis tool with real-time monitoring, quality scoring, and comprehensive DNS comparison.

## 🚀 Live Demo
[https://mohammedsubo.github.io/Network-Latency-Analyzer/](https://mohammedsubo.github.io/Network-Latency-Analyzer/)

## ✨ Features

### Core Features
- **Real-time Latency Monitoring** - Track network performance in real-time
- **Quality Score System** - Advanced scoring algorithm (0-100)
- **DNS Server Comparison** - Compare multiple DNS providers
- **Gaming Mode** - Specialized monitoring for gaming performance
- **PWA Support** - Install as desktop/mobile app

### Advanced Analytics
- P95/P99 percentiles
- Jitter calculation
- Packet loss tracking
- Standard deviation
- Latency distribution histogram

### Export Options
- JSON export
- CSV export
- PDF reports with recommendations

## 🎮 Gaming Mode
Special mode optimized for gamers with:
- Low latency thresholds (< 50ms)
- High frequency testing
- Real-time overlay display
- Gaming-specific recommendations

## 📊 Quality Score Formula
```
Score = 100 - (0.60×L + 0.25×J + 0.15×P)
Where:
- L = avg latency/300ms
- J = jitter/100ms  
- P = packet loss/10%
```

## 🛠️ Technologies
- Pure JavaScript (No frameworks)
- HTML5 Canvas for charts
- CSS3 animations
- Progressive Web App
- Service Workers

## 📱 Installation

### As a Web App
Visit the site and click "Install App" button

### Local Development
```bash
git clone https://github.com/mohammedsubo/Network-Latency-Analyzer.git
cd Network-Latency-Analyzer
# Open index.html in browser
```

## 📈 Usage

1. **Quick Test**: Use preset buttons for fast testing
2. **Custom Target**: Enter any IP or domain
3. **Compare DNS**: Click "Compare All DNS Servers"
4. **Export Results**: Download as JSON/CSV/PDF
5. **Gaming Mode**: Enable for gaming-optimized monitoring

## 🏆 Grading System
- **A+ (95-100)**: Excellent
- **A (90-94)**: Very Good
- **B (75-89)**: Good
- **C (60-74)**: Fair
- **D (40-59)**: Poor
- **F (0-39)**: Very Poor

## 👨‍💻 Developer
Created by Mohammed Subo

## 📝 License
MIT License - Feel free to use and modify!

## 🤝 Contributing
Contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests

## 📧 Contact
[GitHub Profile](https://github.com/mohammedsubo)

---
⭐ If you find this tool useful, please star the repository!