# CertExtract

Here’s a sample GitHub description for your **SSL Chain Extractor** program:

---

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
       - Locate pyinstaller.exe location - c:\users\[USERNAME]\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\scripts\pyinstaller.exe
   - Package into an executable:
     ```bash
     python c:\users\{USERNAME]\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\scripts\pyinstaller.exe --onefile '[path to python script]'
     ```

### Dependencies:
- `cryptography` for handling certificate parsing and generation.
- `requests` for fetching intermediate certificates from the web.
- `certifi` for retrieving trusted root certificates.
- `Tkinter` for the GUI.

### How to Use:
1. **Browse for SSL Certificate**  
   Click **"1. Browse for Certificate"** and select the SSL certificate file from your computer.

2. **Select Save Location**  
   Click **"2. Select Save Location"** and choose a folder where the extracted certificates and full chain will be saved.

3. **Extract Certificates**  
   Once enabled, click **"3. Extract Certificates"** to extract and save the certificate components (leaf, intermediates, root) to the selected folder.

4. **Create Full Chain**  
   Once enabled, click **"4. Create Full Chain"** to generate a `FullChain.cer` file containing the entire certificate chain and save it in the chosen location.
### Screenshots:
Add screenshots of your program's GUI in action to help users visualize the process.


![image](https://github.com/user-attachments/assets/2138f602-cb71-4b12-9bdc-8e0a64664410)


![image](https://github.com/user-attachments/assets/fe1ec081-a3f5-4c01-a9d4-d454793ef5e2)



### License:
MIT License

---

This description provides an overview, features, installation steps, and usage instructions, making it easy for anyone to understand the project and get started. Let me know if you’d like to tweak any part of it!
