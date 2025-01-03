"""
Required libraries:
pip install streamlit PyMuPDF
"""

import streamlit as st
import fitz  # PyMuPDF
import re
import logging
import traceback
from datetime import datetime
import os
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pdf_redactor.log'),
        logging.StreamHandler()
    ]
)

class PDFRedactor:
    def __init__(self):
        self.setup_patterns()
        self.redaction_color = (0, 0, 0)  # Default black

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

    def preview_redactions(self, uploaded_file):
        """Preview PII matches in the document."""
        try:
            doc = fitz.open(stream=uploaded_file.getvalue(), filetype="pdf")
            pii_found = False
            preview_text = []
            
            for page_num in range(len(doc)):
                page = doc[page_num]
                text = page.get_text()
                
                for pii_type in st.session_state.selected_pii_types:
                    pattern = self.pii_patterns[pii_type]
                    matches = list(re.finditer(pattern, text))
                    if matches:
                        pii_found = True
                        preview_text.append(f"Page {page_num + 1}: {pii_type} - {len(matches)} instances")
                        for match in matches:
                            preview_text.append(f"    Found: {match.group()}")
            
            doc.close()
            return pii_found, preview_text
            
        except Exception as e:
            logging.error(f"Error in preview: {str(e)}")
            return False, [f"Error previewing document: {str(e)}"]

    def process_pdf(self, uploaded_file, progress_bar, status_text):
        """Process the PDF and redact PII."""
        try:
            # Create output filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"redacted_{timestamp}.pdf"
            
            # Open the PDF
            doc = fitz.open(stream=uploaded_file.getvalue(), filetype="pdf")
            total_pages = len(doc)
            total_matches = 0
            
            for page_num in range(total_pages):
                status_text.text(f"Processing page {page_num + 1}/{total_pages}")
                page = doc[page_num]
                
                try:
                    text = page.get_text()
                except Exception as e:
                    logging.error(f"Error extracting text from page {page_num + 1}: {str(e)}")
                    continue
                
                # Process each selected PII pattern
                for pii_type in st.session_state.selected_pii_types:
                    pattern = self.pii_patterns[pii_type]
                    matches = self.find_matches(pattern, text)
                    total_matches += len(matches)
                    
                    for match in matches:
                        try:
                            matched_text = match.group()
                            areas = page.search_for(matched_text)
                            
                            if areas:
                                for rect in areas:
                                    # Add padding to the rectangle
                                    padding = 2
                                    redaction_rect = fitz.Rect(
                                        rect.x0 - padding,
                                        rect.y0 - padding,
                                        rect.x1 + padding,
                                        rect.y1 + padding
                                    )
                                    
                                    # Apply visual redaction
                                    page.draw_rect(redaction_rect, color=self.redaction_color, fill=self.redaction_color)
                                    
                                    # Create redaction annotation
                                    redact_annot = page.add_redact_annot(rect)
                                    if redact_annot:
                                        redact_annot.set_colors(stroke=self.redaction_color, fill=self.redaction_color)
                                        page.apply_redactions()
                                    
                        except Exception as e:
                            logging.error(f"Error processing match: {str(e)}")
                            continue
                
                # Update progress
                progress = (page_num + 1) / total_pages
                progress_bar.progress(progress)
                time.sleep(0.1)  # Small delay to show progress
            
            if total_matches > 0:
                # Save to bytes
                output_bytes = doc.write()
                doc.close()
                return output_bytes, output_filename, total_matches
            else:
                doc.close()
                return None, None, 0
            
        except Exception as e:
            error_message = f"Error processing PDF: {str(e)}\n\nTraceback:\n{traceback.format_exc()}"
            logging.error(error_message)
            return None, None, -1

def main():
    st.set_page_config(page_title="PDF PII Redactor", layout="wide")
    
    st.title("PDF PII Redactor")
    st.write("Upload a PDF file to redact Personal Identifiable Information (PII)")
    
    # Initialize session state for PII types
    if 'selected_pii_types' not in st.session_state:
        st.session_state.selected_pii_types = []
    
    # Initialize PDFRedactor
    redactor = PDFRedactor()
    
    # File uploader
    uploaded_file = st.file_uploader("Choose a PDF file", type=['pdf'])
    
    if uploaded_file is not None:
        # PII type selection
        st.write("Select PII types to redact:")
        cols = st.columns(3)
        all_pii_types = list(redactor.pii_patterns.keys())
        
        for i, pii_type in enumerate(all_pii_types):
            col_idx = i % 3
            with cols[col_idx]:
                if st.checkbox(pii_type, key=f"pii_{pii_type}"):
                    if pii_type not in st.session_state.selected_pii_types:
                        st.session_state.selected_pii_types.append(pii_type)
                else:
                    if pii_type in st.session_state.selected_pii_types:
                        st.session_state.selected_pii_types.remove(pii_type)
        
        # Preview and Process buttons
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Preview"):
                if not st.session_state.selected_pii_types:
                    st.warning("Please select at least one PII type to redact.")
                else:
                    with st.spinner("Analyzing document..."):
                        pii_found, preview_text = redactor.preview_redactions(uploaded_file)
                        if pii_found:
                            st.write("PII Found:")
                            for line in preview_text:
                                st.text(line)
                        else:
                            st.info("No PII patterns found in the document.")
        
        with col2:
            if st.button("Process"):
                if not st.session_state.selected_pii_types:
                    st.warning("Please select at least one PII type to redact.")
                else:
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    with st.spinner("Processing PDF..."):
                        output_bytes, output_filename, total_matches = redactor.process_pdf(
                            uploaded_file, progress_bar, status_text
                        )
                        
                        if total_matches > 0:
                            st.success(f"Successfully redacted {total_matches} instances of PII!")
                            st.download_button(
                                label="Download Redacted PDF",
                                data=output_bytes,
                                file_name=output_filename,
                                mime="application/pdf"
                            )
                        elif total_matches == 0:
                            st.info("No PII found to redact.")
                        else:
                            st.error("An error occurred during processing.")
                        
                        # Clear progress bar and status
                        progress_bar.empty()
                        status_text.empty()

if __name__ == "__main__":
    main()