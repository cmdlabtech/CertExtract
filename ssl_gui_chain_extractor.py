import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk  # Importing Pillow for image handling
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import certifi
import requests

class SSLChainExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSL Chain Extractor")
        self.root.geometry("295x160")

        self.cert_file = None  # SSL certificate file path
        self.save_directory = None  # Directory to save extracted files

        # Create UI Elements
        self.create_widgets()

    def create_widgets(self):
        # Instructions
        self.label = tk.Label(self.root, text="Select your SSL certificate:")
        self.label.grid(row=0, column=0, columnspan=2, pady=10)

        # Browse Certificate button
        self.browse_button = tk.Button(self.root, text="1. Browse for Certificate", command=self.browse_cert)
        self.browse_button.grid(row=1, column=0, padx=5, pady=5)

        # Select Save Location button
        self.save_dir_button = tk.Button(self.root, text="2. Select Save Location", command=self.select_save_directory)
        self.save_dir_button.grid(row=2, column=0, padx=5, pady=5)

        # Extract and Create buttons (initially disabled)
        self.extract_button = tk.Button(self.root, text="3. Extract Certificates", command=self.extract_certificates, state=tk.DISABLED)
        self.extract_button.grid(row=1, column=1, padx=5, pady=5)

        self.fullchain_button = tk.Button(self.root, text="4. Create Full Chain", command=self.create_full_chain, state=tk.DISABLED)
        self.fullchain_button.grid(row=2, column=1, padx=5, pady=5)

        # Status label to display messages (no file path will be displayed)
        self.chain_status_label = tk.Label(self.root, text="")
        self.chain_status_label.grid(row=3, column=0, columnspan=2, pady=10)

    def browse_cert(self):
        self.cert_file = filedialog.askopenfilename(title="Select SSL Certificate",
                                                    filetypes=(("PEM files", "*.pem;*.crt;*.cer"), ("All files", "*.*")))
        if self.cert_file:
            # Enable the next steps
            self.extract_button.config(state=tk.NORMAL)
            self.fullchain_button.config(state=tk.NORMAL)

            # Display confirmation instead of file path
            self.chain_status_label.config(text="Certificate selected!")
        else:
            messagebox.showwarning("No File", "No file was selected")

    def select_save_directory(self):
        self.save_directory = filedialog.askdirectory(title="Select Root Save Directory")
        if self.save_directory:
            self.chain_status_label.config(text="Save location selected!")
        else:
            messagebox.showwarning("No Directory", "No directory was selected")

    def extract_certificates(self):
        if not self.cert_file:
            messagebox.showwarning("No File", "Please select an SSL certificate first")
            return
        if not self.save_directory:
            messagebox.showwarning("No Save Directory", "Please select a save directory first")
            return

        try:
            with open(self.cert_file, 'rb') as f:
                pem_data = f.read()

            # Load all certificates from the file
            certs = self.load_certificates_from_pem(pem_data)
            if not certs:
                messagebox.showerror("Error", "No valid certificates found in the file.")
                return

            # Save the certificates with proper labeling (leaf, intermediates, root)
            self.save_certificates(certs)

            self.chain_status_label.config(text="Certificates extracted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error extracting certificates: {e}")

    def save_certificates(self, certs):
        """
        Save the certificates and label them as 'leaf', 'intermediate', or 'root' in the selected directory.
        """
        try:
            for index, cert in enumerate(certs, 1):
                if index == 1:
                    label = "leaf"
                elif index < len(certs):
                    label = f"intermediate_{index - 1}"
                else:
                    label = "root"

                # Construct the full path for saving
                filename = os.path.join(self.save_directory, f"cert_{label}.cer")
                with open(filename, 'wb') as f:
                    f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            self.chain_status_label.config(text="Certificates saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving certificates: {e}")

    def create_full_chain(self):
        if not self.cert_file:
            messagebox.showwarning("No File", "Please select an SSL certificate first")
            return
        if not self.save_directory:
            messagebox.showwarning("No Save Directory", "Please select a save directory first")
            return

        try:
            with open(self.cert_file, 'rb') as f:
                pem_data = f.read()

            # Load the initial certificates from the file
            certs = self.load_certificates_from_pem(pem_data)
            if not certs:
                messagebox.showerror("Error", "No valid certificates found in the file.")
                return

            chain = certs.copy()
            last_cert = certs[-1]

            # Build the chain by fetching intermediates
            while True:
                issuer = last_cert.issuer
                subject = last_cert.subject

                if issuer == subject:
                    # Self-signed certificate (likely a root)
                    break

                intermediates = self.fetch_intermediate_certificates(last_cert)
                if not intermediates:
                    break  # Cannot fetch further intermediates

                # Avoid duplicates
                for intermediate in intermediates:
                    if intermediate not in chain:
                        chain.append(intermediate)

                last_cert = intermediates[0]  # Move up the chain

            # If the root certificate is not self-signed, add it from certifi
            if not self.is_self_signed(chain[-1]):
                root_cert = self.fetch_root_certificate(chain[-1])
                if root_cert:
                    chain.append(root_cert)
                else:
                    messagebox.showwarning("Warning", "Root certificate could not be found!")

            # Save the chain to FullChain.cer in the selected directory
            full_chain_file = os.path.join(self.save_directory, 'FullChain.cer')
            with open(full_chain_file, 'wb') as f:
                for cert in chain:
                    f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

            self.chain_status_label.config(text=f"FullChain.cer created successfully at {full_chain_file}!")
        except Exception as e:
            messagebox.showerror("Error", f"Error creating FullChain.cer: {e}")

    def load_certificates_from_pem(self, pem_data):
        """
        Load all certificates from a PEM file.
        """
        certs = []
        pem_blocks = pem_data.split(b'-----END CERTIFICATE-----')
        for block in pem_blocks:
            if b'-----BEGIN CERTIFICATE-----' in block:
                block += b'-----END CERTIFICATE-----\n'
                try:
                    cert = x509.load_pem_x509_certificate(block, default_backend())
                    certs.append(cert)
                except Exception as e:
                    print(f"Error loading certificate: {e}")
        return certs

    def is_self_signed(self, cert):
        """
        Check if the certificate is self-signed.
        """
        return cert.issuer == cert.subject

    def fetch_root_certificate(self, cert):
        """
        Attempt to fetch the root certificate from certifi based on issuer.
        """
        root_certificates = self.load_certifi_root_certs()
        issuer = cert.issuer

        # Try to find a root certificate that matches the issuer
        for root_cert in root_certificates:
            if root_cert.subject == issuer:
                return root_cert
        return None

    def load_certifi_root_certs(self):
        """
        Load trusted root certificates from the certifi bundle.
        """
        root_certs = []
        with open(certifi.where(), 'rb') as f:
            pem_data = f.read()

        pem_blocks = pem_data.split(b'-----END CERTIFICATE-----')
        for block in pem_blocks:
            if b'-----BEGIN CERTIFICATE-----' in block:
                block += b'-----END CERTIFICATE-----\n'
                try:
                    cert = x509.load_pem_x509_certificate(block, default_backend())
                    root_certs.append(cert)
                except Exception as e:
                    print(f"Error loading root certificate: {e}")
        return root_certs

    def fetch_intermediate_certificates(self, cert):
        """
        Fetch intermediate certificates using the Authority Information Access extension.
        """
        intermediates = []
        try:
            aia_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            aia = aia_extension.value

            for access_description in aia:
                if access_description.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    url = access_description.access_location.value
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        cert_data = response.content

                        # Determine if the certificate is in DER or PEM format
                        if b'-----BEGIN CERTIFICATE-----' in cert_data:
                            intermediate_cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                        else:
                            intermediate_cert = x509.load_der_x509_certificate(cert_data, default_backend())

                        intermediates.append(intermediate_cert)
                    else:
                        print(f"Failed to fetch intermediate certificate from {url}")
        except x509.ExtensionNotFound:
            print("AIA extension not found in the certificate.")
        except Exception as e:
            print(f"Error fetching intermediate certificates: {e}")
        return intermediates

# Run the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = SSLChainExtractorApp(root)
    root.mainloop()
