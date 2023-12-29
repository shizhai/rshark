from pathlib import Path
from tkinter import filedialog

filename = filedialog.askopenfilename()
if filename:
    # Read and print the content (in bytes) of the file.
    print(Path(filename).read_bytes())
else:
    print("No file selected.")