import sys

if len(sys.argv) < 2:
    print("Usage: python tamper_pdf.py <pdf_file>")
    sys.exit(1)

file_path = sys.argv[1]
try:
    with open(file_path, "ab") as f:
        f.write(b"\n% Hacker was here!\n")
    print(f"Successfully tampered with {file_path}")
    print("Please run the verify script again to see the failure (Invariant I2).")
except Exception as e:
    print(f"Error: {e}")
