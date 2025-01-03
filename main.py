"""
Required libraries:
pip install PyMuPDF
pip install tkinter
pip install re
"""

import tkinter as tk
from tkinter import filedialog, ttk, messagebox, colorchooser
import re
import fitz  # PyMuPDF
import logging
import traceback
from datetime import datetime
import os
import threading
from queue import Queue
import time

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s',
    handlers=[
        logging.FileHandler('pdf_redactor.log'),
        logging.StreamHandler()
    ]
)

class PDFRedactor:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF PII Redactor")
        self.selected_file = None
        self.redaction_color = (0, 0, 0)  # Default black
        self.processing = False
        self.cancel_processing = False
        self.setup_patterns()
        self.setup_ui()
        
        # Set up error handling for the UI thread
        self.root.report_callback_exception = self.handle_callback_error

    def handle_callback_error(self, exc, val, tb):
        error_message = f"Error: {val}\n\nTraceback:\n{''.join(traceback.format_tb(tb))}"
        logging.error(error_message)
        self.status_var.set(f"Error: {val}")
        messagebox.showerror("Error", error_message)

    def setup_patterns(self):
        self.pii_patterns = {
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Phone': r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
            'Credit Card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'Date of Birth': r'\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](\d{2}|\d{4})\b',
            'IP Address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'Address': r'\b\d+\s+[A-Za-z\s.]+,\s*[A-Za-z\s]+,\s*[A-Z]{2}\s+\d{5}(-\d{4})?\b'
        }

    def find_matches(self, pattern, text):
        """Find regex matches without using signals."""
        try:
            return list(re.finditer(pattern, text))
        except Exception as e:
            logging.error(f"Error in regex search: {str(e)}")
            return []

    def setup_ui(self):
        # Create main frame with padding
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # File selection frame
        file_frame = ttk.LabelFrame(self.main_frame, text="File Selection", padding="5")
        file_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.file_label = ttk.Label(file_frame, text="No file selected")
        self.file_label.grid(row=0, column=0, padx=5)
        
        ttk.Button(file_frame, text="Select PDF", command=self.select_file).grid(row=0, column=1, padx=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(self.main_frame, text="Redaction Options", padding="5")
        options_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Color selection
        ttk.Button(options_frame, text="Select Redaction Color", 
                  command=self.choose_color).grid(row=0, column=0, pady=5)
        
        # PII type selection with tooltips
        ttk.Label(options_frame, text="Select PII types to redact:").grid(row=1, column=0, pady=5)
        
        self.pii_vars = {}
        for i, (pii_type, pattern) in enumerate(self.pii_patterns.items()):
            var = tk.BooleanVar(value=True)
            self.pii_vars[pii_type] = var
            cb = ttk.Checkbutton(options_frame, text=pii_type, variable=var)
            cb.grid(row=i+2, column=0, sticky=tk.W)
            self.create_tooltip(cb, f"Pattern: {pattern}")
        
        # Progress frame
        progress_frame = ttk.LabelFrame(self.main_frame, text="Progress", padding="5")
        progress_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5, padx=5)
        
        self.progress = ttk.Progressbar(progress_frame, length=300, mode='determinate')
        self.progress.grid(row=0, column=0, pady=5, padx=5)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_label = ttk.Label(progress_frame, textvariable=self.status_var, wraplength=300)
        self.status_label.grid(row=1, column=0, pady=5)
        
        # Cancel button (hidden by default)
        self.cancel_button = ttk.Button(progress_frame, text="Cancel", command=self.cancel_processing_task)
        
        # Action buttons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.preview_button = ttk.Button(button_frame, text="Preview", command=self.preview_redactions)
        self.preview_button.grid(row=0, column=0, padx=5)
        
        self.process_button = ttk.Button(button_frame, text="Process", command=self.process_current_file)
        self.process_button.grid(row=0, column=1, padx=5)

    def create_tooltip(self, widget, text):
        def show_tooltip(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            
            label = ttk.Label(tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1)
            label.pack()
            
            def hide_tooltip():
                tooltip.destroy()
            
            widget.tooltip = tooltip
            widget.bind('<Leave>', lambda e: hide_tooltip())
            
        widget.bind('<Enter>', show_tooltip)

    def choose_color(self):
        color = colorchooser.askcolor(title="Choose Redaction Color")
        if color[0]:  # color is ((R,G,B), #RRGGBB)
            self.redaction_color = tuple(int(c/255) for c in color[0])  # Normalize to 0-1 range for PyMuPDF

    def select_file(self):
        filename = filedialog.askopenfilename(
            title="Select PDF file",
            filetypes=[("PDF files", "*.pdf")]
        )
        if filename:
            self.selected_file = filename
            self.file_label.config(text=os.path.basename(filename))
            logging.info(f"Selected file: {filename}")

    def update_ui_state(self, processing=False):
        state = 'disabled' if processing else 'normal'
        self.preview_button['state'] = state
        self.process_button['state'] = state
        if processing:
            self.cancel_button.grid(row=2, column=0, pady=5)
        else:
            self.cancel_button.grid_remove()
        self.root.update()

    def cancel_processing_task(self):
        self.cancel_processing = True
        self.status_var.set("Canceling...")
        self.root.update()

    def preview_redactions(self):
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a PDF file first.")
            return
            
        try:
            doc = fitz.open(self.selected_file)
            pii_found = False
            preview_text = "PII Found:\n\n"
            
            for page_num in range(len(doc)):
                page = doc[page_num]
                text = page.get_text()
                
                for pii_type, var in self.pii_vars.items():
                    if var.get():
                        pattern = self.pii_patterns[pii_type]
                        matches = list(re.finditer(pattern, text))
                        if matches:
                            pii_found = True
                            preview_text += f"Page {page_num + 1}: {pii_type} - {len(matches)} instances\n"
                            for match in matches:
                                preview_text += f"    Found: {match.group()}\n"
            
            doc.close()
            
            if pii_found:
                messagebox.showinfo("Preview Results", preview_text)
            else:
                messagebox.showinfo("Preview Results", "No PII patterns found in the document.")
                
        except Exception as e:
            logging.error(f"Error in preview: {str(e)}")
            messagebox.showerror("Error", f"Error previewing document: {str(e)}")

    def process_current_file(self):
        if not self.selected_file:
            messagebox.showwarning("Warning", "Please select a PDF file first.")
            return
        
        if self.processing:
            return
            
        self.processing = True
        self.cancel_processing = False
        self.update_ui_state(processing=True)
        
        # Start processing in a separate thread
        thread = threading.Thread(target=self.process_pdf_thread, args=(self.selected_file,))
        thread.daemon = True
        thread.start()

    def process_pdf_thread(self, input_path):
        try:
            logging.info(f"Starting PDF processing for: {input_path}")
            self.status_var.set("Processing...")
            self.progress['value'] = 0
            
            # Create output filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"{input_path[:-4]}_redacted_{timestamp}.pdf"
            logging.info(f"Output will be saved to: {output_path}")
            
            # Open the PDF
            logging.debug("Opening PDF document")
            doc = fitz.open(input_path)
            total_pages = len(doc)
            logging.info(f"Document has {total_pages} pages")
            
            total_matches = 0
            
            for page_num in range(total_pages):
                if self.cancel_processing:
                    doc.close()
                    logging.info("Processing cancelled by user")
                    self.root.after(0, self.cleanup_after_processing, "Canceled by user")
                    return
                
                logging.debug(f"Processing page {page_num + 1}/{total_pages}")
                page = doc[page_num]
                
                try:
                    text = page.get_text()
                    logging.debug(f"Successfully extracted text from page {page_num + 1}")
                except Exception as e:
                    logging.error(f"Error extracting text from page {page_num + 1}: {str(e)}")
                    continue
                
                # Process each selected PII pattern
                for pii_type, var in self.pii_vars.items():
                    if var.get():
                        pattern = self.pii_patterns[pii_type]
                        logging.debug(f"Searching for {pii_type} patterns on page {page_num + 1}")
                        
                        matches = self.find_matches(pattern, text)
                        match_count = len(matches)
                        total_matches += match_count
                        logging.debug(f"Found {match_count} matches for {pii_type}")
                        
                        # Process matches in batches
                        batch_size = 5
                        for i in range(0, len(matches), batch_size):
                            if self.cancel_processing:
                                break
                            
                            batch = matches[i:i + batch_size]
                            for match in batch:
                                try:
                                    # Get the matched text
                                    matched_text = match.group()
                                    logging.debug(f"Processing match: {matched_text[:3]}...")
                                    
                                    # Find all instances of this text on the page
                                    areas = page.search_for(matched_text)
                                    logging.debug(f"Found {len(areas) if areas else 0} instances on page")
                                    
                                    if areas:
                                        for rect in areas:
                                            try:
                                                # Add padding to the rectangle
                                                padding = 2
                                                redaction_rect = fitz.Rect(
                                                    rect.x0 - padding,
                                                    rect.y0 - padding,
                                                    rect.x1 + padding,
                                                    rect.y1 + padding
                                                )
                                                
                                                # First apply the visual redaction
                                                page.draw_rect(redaction_rect, color=self.redaction_color, fill=self.redaction_color)
                                                logging.debug("Applied visual redaction")
                                                
                                                # Then create a redaction annotation
                                                redact_annot = page.add_redact_annot(rect)
                                                if redact_annot:
                                                    redact_annot.set_colors(stroke=self.redaction_color, fill=self.redaction_color)
                                                    page.apply_redactions()
                                                    logging.debug("Applied redaction annotation")
                                                else:
                                                    logging.warning("Failed to create redaction annotation")
                                                    
                                            except Exception as e:
                                                logging.error(f"Error applying redaction: {str(e)}")
                                                continue
                                    
                                except Exception as e:
                                    logging.error(f"Error processing match: {str(e)}")
                                    continue
                            
                            # Update progress more frequently
                            progress = (page_num * 100 + (i / len(matches) * 100 if matches else 100)) / total_pages
                            self.root.after(0, self.update_progress, progress)
                            
                            # Give UI a chance to breathe
                            time.sleep(0.02)
                
                logging.info(f"Completed processing page {page_num + 1}")
            
            if not self.cancel_processing:
                if total_matches > 0:
                    # Save the redacted PDF
                    logging.info("Saving redacted PDF")
                    doc.save(output_path)
                    success_message = f"Complete! Redacted {total_matches} instances. Saved as: {os.path.basename(output_path)}"
                    self.root.after(0, self.cleanup_after_processing, success_message)
                    logging.info(success_message)
                else:
                    logging.info("No matches found to redact")
                    self.root.after(0, self.cleanup_after_processing, "No PII found to redact")
            
            doc.close()
            logging.info("Document closed successfully")
            
        except Exception as e:
            error_message = f"Error processing PDF: {str(e)}\n\nTraceback:\n{traceback.format_exc()}"
            logging.error(error_message)
            self.root.after(0, self.cleanup_after_processing, f"Error: {str(e)}")

    def update_progress(self, value):
        try:
            self.progress['value'] = value
            self.status_var.set(f"Processing... {value:.1f}%")
            self.root.update()
        except Exception as e:
            logging.error(f"Error updating progress: {str(e)}")

    def cleanup_after_processing(self, status_message):
        try:
            self.processing = False
            self.cancel_processing = False
            self.status_var.set(status_message)
            self.progress['value'] = 0 if "Error" in status_message or "Canceled" in status_message else 100
            self.update_ui_state(processing=False)
            
            if "Error" in status_message:
                messagebox.showerror("Error", status_message)
            elif "Canceled" not in status_message:
                messagebox.showinfo("Success", status_message)
        except Exception as e:
            logging.error(f"Error in cleanup: {str(e)}")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = PDFRedactor(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Application crashed: {str(e)}\n\nTraceback:\n{traceback.format_exc()}")
        messagebox.showerror("Critical Error", f"Application crashed: {str(e)}")