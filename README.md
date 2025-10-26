## Quantum-Digital-Forensic-Toolkit ⚛️💻
A Python-based GUI application for digital forensics and cybersecurity tasks, inspired by quantum computing principles. This toolkit provides file analysis, batch scanning for sensitive information, password evaluation, secure key generation, and report export — all in an interactive and user-friendly interface.

## Features
 # File Tools
Compute file hashes (MD5,SHA1,SHA256).
Calculate file entropy to assess data randomness.
Extract essential file metadata (timestamps, size).
 # Batch Scanner
Recursively scan folders for sensitive data patterns.
Detect emails, AWS keys, private key blocks, SSN-like, and credit card patterns.
 # Password Tools
Evaluate classical password strength.
Simulate quantum-inspired brute-force attempts using Grover-like estimation for reduced attack time.
 # Key Generator
Generate cryptographically secure random keys of customizable length.
 # Reports
Export all results and operation logs to CSV or TXT for documentation and forensic purposes.
 # Responsive GUI
Built with Tkinter Notebook and threading for smooth operation, even on large datasets.
 # Quantum-Inspired Concepts
The toolkit leverages conceptual interpretations of quantum mechanics to offer advanced estimation for security tasks.

## Concept	Application
Superposition Simulation	Conceptually represents multiple password states simultaneously for analysis.
Grover-like Search Estimation	Provides a theoretical quantum-inspired reduction in brute-force attempts estimation for passwords, highlighting modern security challenges.
 # Installation
To set up the toolkit, follow these simple steps:
Clone the repository (replace yourusername with the actual username when available):

## Bash
 git clone https://github.com/yourusername/Quantum-Forensics-Toolkit.git
 cd Quantum-Forensics-Toolkit
 Install dependencies (Assuming standard Python libraries like Tkinter and others are required. You may need to create a requirements.txt):

## How to Use
 Launch the Toolkit
 Run the main Python file to start the application:
  # Bash
 python Quantum_Forensics_Toolkit.py
 Dashboard
 Provides an overview of all available modules.
 Offers quick access to recent scans and operations.

 # File Tools
Select a file using the Browse button.
Compute file hashes (MD5,SHA1,SHA256).
Analyze file entropy and view file metadata (creation/modification/access times, file size).

 # Batch Scanner
 Select a folder to scan recursively.
 Choose the type of sensitive data to detect (emails, AWS keys, private keys, SSNs, credit card   numbers).
 Start the scan and view the results directly in the GUI.
 Use the export option to save results to CSV or TXT.

 # Password Tools
 Enter a password to analyze.
 Check classical strength and the quantum-inspired brute-force estimates.
 View the entropy score and strength classification (Weak,Reasonable,Strong,Very Strong).

# Key Generator
 Enter the desired key length.
 Click Generate Key to create a cryptographically secure key.
 Copy the key for cryptographic or security use.

 # Reports 
 View logs of all operations performed within the toolkit.

Export logs for forensic documentation or auditing.

