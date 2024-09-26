## SSL Chain Extractor

### Overview
**SSL Chain Extractor** is a simple Python-based utility with a graphical user interface (GUI) that extracts the full certificate chain (leaf, intermediate, and root certificates) from a given SSL certificate. It provides the option to break out each certificate into separate files and generate a `FullChain.cer` file for easy integration in applications requiring a complete certificate chain.

The program supports PEM, CRT, and CER formats and includes functionality to fetch missing intermediate or root certificates using the Authority Information Access (AIA) extension or the trusted root certificates available in the system or via `certifi`.

### Key Features:
- **Extract Certificates**: Extracts the leaf, intermediate, and root certificates from a provided SSL certificate file.
- **Save Certificates**: Saves each certificate as a separate file (leaf, intermediate(s), and root).
- **Create FullChain.cer**: Combines the entire certificate chain into a `FullChain.cer` file for easy use.
- **Fetch Intermediate/Root Certificates**: Automatically fetches missing intermediate and root certificates from the web using AIA or from trusted root stores (`certifi`).
- **Simple GUI**: Intuitive user interface built with Tkinter for easy file selection and execution.

### Installation & Requirements:
1. **Python 3.7+** is required.
2. Install the necessary dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. For packaging into a standalone executable:
   - Install PyInstaller:
     ```bash
     pip install pyinstaller
     ```
   - Locate PyInstaller path:
     ```bash
     pip uninstall pyinstaller
     ```
       - Locate pyinstaller.exe location - `C:\users\{USERNAME}\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\scripts\pyinstaller.exe`
       - Package into an executable:
     ```bash
     python [PyInstaller LOCATION] --noconsole --onefile [path to python script]
     ```

### Dependencies:
- `cryptography` for handling certificate parsing and generation.
- `requests` for fetching intermediate certificates from the web.
- `certifi` for retrieving trusted root certificates.
- `Tkinter` for the GUI.

### How to Use:
1. **Select an SSL Certificate**: Use the GUI to select a `.pem`, `.crt`, or `.cer` file.
2. **Extract Certificates**: Click the "Extract Certificates" button to extract the leaf, intermediate, and root certificates.
3. **Create FullChain**: Optionally, click "Create FullChain.cer" to generate a single file containing the entire certificate chain.
4. **Save Output**: Each certificate is saved to a separate file (e.g., `cert_leaf.cer`, `cert_intermediate_1.cer`, `cert_root.cer`).

### Screenshots:
Add screenshots of your program's GUI in action to help users visualize the process.

### License:
MIT License
