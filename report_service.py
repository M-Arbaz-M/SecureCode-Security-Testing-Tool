from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

class ReportService:
    def generate_pdf_report(self, input_code, vulnerability_report):
        """
        Generates a PDF report in-memory and returns it as a binary stream.
        This will allow the user to download the report directly via Streamlit.
        """

        pdf_buffer = BytesIO()

        c = canvas.Canvas(pdf_buffer, pagesize=letter)
        width, height = letter
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, height - 50, "Python Code Vulnerability Report")
        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, height - 100, "Input Code:")
        c.setFont("Helvetica", 10)

        code_lines = input_code.split("\n")
        y_position = height - 130
        for i, line in enumerate(code_lines):
            if y_position < 50:
                c.showPage()  
                y_position = height - 50  
            c.drawString(100, y_position, line)
            y_position -= 12 

        c.setFont("Helvetica-Bold", 12)
        c.drawString(100, y_position - 20, "Vulnerability Report:")
        c.setFont("Helvetica", 10)

        report_lines = vulnerability_report.split("\n")
        y_position -= 50
        for i, line in enumerate(report_lines):
            if y_position < 50: 
                c.showPage()  
                y_position = height - 50
            c.drawString(100, y_position, line)
            y_position -= 12 

        c.save()

        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()