A comprehensive and interactive web-based application fuzzer designed for automated vulnerability testing. Built using **Flask**, **Boofuzz**, **WebSockets**, and **Chart.js**, this tool allows users to test web endpoints against common attack payloads, visualize results in real-time, and generate downloadable reports.

---

## 🚀 Features

- ✅ **User-friendly dashboard** with form-based input for target URLs and endpoints.
- 📡 **Real-time fuzzing progress** updates using WebSockets.
- 📊 **Visual reports** including:
  - Accuracy vs False Positives
  - Fuzzing Progress Over Time
  - Comparison with Other Tools
- 🧪 **Payload-based vulnerability detection** using Boofuzz.
- 📁 **Automated report generation** in downloadable formats.
- 🔐 Designed to simulate attacks like SQL Injection, XSS, Path Traversal, and more.

---

## 🛠️ Tech Stack

- **Frontend**: HTML, CSS, JavaScript, Chart.js
- **Backend**: Python (Flask, Flask-SocketIO)
- **Fuzzing Engine**: [Boofuzz]
- **Visualization**: Chart.js
- **Report Format**: JSON (can be extended to HTML, PDF)

---

## 🧪 Example Payloads Tested

- `' OR '1'='1`
- `<script>alert('XSS')</script>`
- `../../etc/passwd`
- `admin' --`
- `javascript:alert(1)`
- `%00`, `%27`, `'`

---

## 📉 Sample Charts Explained

- **Accuracy vs False Positives**: Displays effectiveness of the detection engine.
- **Fuzzing Progress Over Time**: Shows real-time execution status.
- **Comparison with Other Tools**: Benchmarks your fuzzer against others.

---

SDG Relevance
This project contributes to UN SDG Goal 9: Industry, Innovation and Infrastructure by promoting secure and resilient digital infrastructure through automated cybersecurity testing tools.

🔮 Future Work
Add support for authenticated fuzzing sessions.

Extend reporting to HTML/PDF with CVSS scoring.

Integrate with CI/CD pipelines.

Enhance payload set with AI-generated variants.
