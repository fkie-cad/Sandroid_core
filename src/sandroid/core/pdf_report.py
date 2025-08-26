"""Adapted From https://github.com/jurasec/python-reportlab-example"""

import json
import os

from PIL import Image as PILImage
from reportlab.graphics.shapes import Drawing, Line
from reportlab.lib.colors import Color
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, inch
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from . import timeline_generator
from .toolbox import Toolbox


class FooterCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self.pages = []
        self.width, self.height = A4

    def showPage(self):
        self.pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self.pages)
        for page in self.pages:
            self.__dict__.update(page)
            if self._pageNumber > 1:
                self.draw_canvas(page_count)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_canvas(self, page_count):
        page = "Page %s of %s" % (self._pageNumber, page_count)
        x = 128
        self.saveState()
        self.setStrokeColorRGB(0, 0, 0)
        self.setLineWidth(0.5)
        self.drawImage(
            "assets/Fraunhofer_Logo.jpg",
            self.width - inch * 8 - 5,
            self.height - 50,
            width=100,
            height=20,
            preserveAspectRatio=True,
        )
        self.drawImage(
            "assets/sandroid_logo.png",
            self.width - inch * 2,
            self.height - 50,
            width=100,
            height=20,
            preserveAspectRatio=True,
            mask="auto",
        )
        # self.line(30, 760, A4[0] - 50, 760)
        self.line(66, 58, A4[0] - 66, 58)
        self.setFont("Times-Roman", 10)
        self.drawString(A4[0] - x, 45, page)
        self.restoreState()


class PDFReport:
    data = None
    inputFileName = ""
    # logger = Toolbox.logger_factory("pdf_report")

    def __init__(self, path, result_file_to_parse):
        self.inputFileName = result_file_to_parse
        inputFile = open(self.inputFileName, "rb")
        self.data = json.loads(inputFile.read())

        self.path = path
        self.styleSheet = getSampleStyleSheet()
        self.elements = []

        self.header_font_color = Color((12.0 / 255), (154.0 / 255), (124.0 / 255), 1)
        self.highlight_color = Color((255 / 255), (111 / 255), (89.0 / 255), 1)
        self.small_title_font_color = Color(
            (12.0 / 255), (154.0 / 255), (124.0 / 255), 1
        )
        self.table_line_color = Color((234.0 / 255), (210.0 / 255), (172.0 / 255), 1)
        self.table_header_background_color = Color(
            (31.0 / 255), (32.0 / 255), (65.0 / 255), 1
        )
        self.white = Color(1, 1, 1, 1)

        self.firstPage()
        self.summaryTableMaker()
        if "Changed Files" in self.data.keys():
            self.timelinePage()
        self.pageHeader("Detailed Report")
        for collected_data_item in self.data.keys():
            match collected_data_item:
                case "Changed Files":
                    self.changedFilesTableMaker()
                case "New Files":
                    self.generalTableMaker("New Files")
                case "Network":
                    self.generalTableMaker("Network")
                    self.generalTableMaker("Network IP:Port (send/recv)")
                case "Deleted Files":
                    self.generalTableMaker("Deleted Files")
                case "Processes":
                    self.generalTableMaker("Processes")
                case "Listening Sockets":
                    self.generalTableMaker("Listening Sockets")
        for collected_data_item in self.data["Other Data"].keys():
            match collected_data_item:
                case "APK Hashes":
                    self.APKTableMaker()
                case "Artifact Hashes":
                    self.newFileHashesTableMaker()
                    self.changedFileHashesTableMaker()
                case "AI Action Summary":
                    pass  # Make page that displays action summary

        if len(os.listdir(f"{os.getenv('RAW_RESULTS_PATH')}screenshots")) != 0:
            self.pageHeader("Screenshots")
            self.image_grid()

        # Build
        self.doc = SimpleDocTemplate(path, pagesize=A4)
        self.doc.multiBuild(self.elements, canvasmaker=FooterCanvas)

        inputFile.close()

    def firstPage(self):
        img = Image("assets/Fraunhofer_Logo.jpg")
        img.drawHeight = 0.5 * inch
        img.drawWidth = 0.5 * inch
        img.hAlign = "LEFT"
        self.elements.append(img)

        spacer = Spacer(30, 100)
        self.elements.append(spacer)

        img = Image("assets/sandroid_logo.png")
        img.drawHeight = 2.5 * inch
        img.drawWidth = 2.5 * inch
        self.elements.append(img)

        spacer = Spacer(10, 40)
        self.elements.append(spacer)

        titleText = "Sandroid Forensic Report"
        titleStyle = ParagraphStyle(
            "Hed0",
            fontName="Helvetica-Bold",
            fontSize=30,
            leading=14,
            justifyBreaks=1,
            alignment=TA_CENTER,
            justifyLastLine=1,
        )
        title = Paragraph(titleText, titleStyle)
        self.elements.append(title)

        # self.draw_panel(x=300,y=350,width=200,height=100,
        #        main_number="112",
        #        title="High Severity",
        #        symbol="\u26A0")

        spacer = Spacer(10, 200)
        self.elements.append(spacer)

        psDetalle = ParagraphStyle(
            "Resumen",
            fontSize=9,
            leading=14,
            justifyBreaks=1,
            alignment=TA_LEFT,
            justifyLastLine=1,
        )
        text = (
            """SANDROID FORENSIC REPORT<br/>
        Device Name: """
            + str(self.data["Device Name"])
            + """<br/>"""
        )

        if (
            "Other Data" in self.data
            and "AI Action Overview" in self.data["Other Data"]
        ):
            text += (
                """Action: """
                + str(self.data["Other Data"]["AI Action Overview"][0])
                + """<br/>"""
            )

        text += (
            """Emulator relative action timestamp: """
            + str(self.data["Emulator relative action timestamp"])
            + """<br/>
        Action Duration: """
            + str(self.data["Action Duration"])
            + """ Seconds<br/>
        """
        )
        paragraphReportSummary = Paragraph(text, psDetalle)
        self.elements.append(paragraphReportSummary)
        self.elements.append(PageBreak())

    def pageHeader(self, content):
        spacer = Spacer(10, 30)
        self.elements.append(spacer)
        psHeaderText = ParagraphStyle(
            "Hed0",
            fontSize=20,
            alignment=TA_LEFT,
            borderWidth=3,
            textColor=self.header_font_color,
            fontName="Helvetica-Bold",
        )
        paragraphReportHeader = Paragraph(content, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 20)
        self.elements.append(spacer)

        d = Drawing(500, 1)
        line = Line(-100, 0, 600, 0)
        line.strokeColor = self.header_font_color
        line.strokeWidth = 2
        d.add(line)
        self.elements.append(d)

        spacer = Spacer(10, 40)
        self.elements.append(spacer)

    def timelinePage(self):
        psHeaderText = ParagraphStyle(
            "Hed0",
            fontSize=12,
            alignment=TA_LEFT,
            borderWidth=3,
            textColor=self.small_title_font_color,
        )
        text = "Timeline"
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        timeline_generator.parse_timeline(self.inputFileName)

        img = Image(f"{os.getenv('RESULTS_PATH')}timeline.png")
        img.drawWidth, img.drawHeight = A4
        img.drawWidth = img.drawWidth * 0.7
        img.drawHeight = img.drawHeight * 0.8
        self.elements.append(img)

    def generalTableMaker(self, json_section_to_tableize):
        psHeaderText = ParagraphStyle(
            "Hed0",
            fontSize=12,
            alignment=TA_LEFT,
            borderWidth=3,
            textColor=self.small_title_font_color,
        )
        text = json_section_to_tableize
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)
        """
        Create the line items
        """
        data = [self.make_header(["No.", "Artifact"])]
        lineNum = 1
        formattedLineData = []

        alignStyle = [
            ParagraphStyle(name="01", alignment=TA_CENTER),
            ParagraphStyle(name="02", alignment=TA_LEFT),
            ParagraphStyle(name="03", alignment=TA_CENTER),
            ParagraphStyle(name="04", alignment=TA_CENTER),
            ParagraphStyle(name="05", alignment=TA_CENTER),
        ]
        fontSize = 8
        for row in self.data[json_section_to_tableize]:
            lineData = [str(lineNum), row]
            # data.append(lineData)
            columnNumber = 0
            for item in lineData:
                ptext = "<font size='%s'>%s</font>" % (fontSize - 1, item)
                p = Paragraph(ptext, alignStyle[columnNumber])
                formattedLineData.append(p)
                columnNumber = columnNumber + 1
            data.append(formattedLineData)
            formattedLineData = []
            lineNum = lineNum + 1

        table = Table(data, colWidths=[50, 450])
        tStyle = TableStyle(
            [  # ('GRID',(0, 0), (-1, -1), 0.5, grey),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                # ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("LINEABOVE", (0, 0), (-1, -1), 1, self.table_line_color),
                ("BACKGROUND", (0, 0), (-1, 0), self.table_header_background_color),
                ("SPAN", (0, -1), (-2, -1)),
            ]
        )
        table.setStyle(tStyle)
        self.elements.append(table)
        self.elements.append(PageBreak())

    def summaryTableMaker(self):
        psHeaderText = ParagraphStyle(
            "Hed0",
            fontSize=12,
            alignment=TA_LEFT,
            borderWidth=3,
            textColor=self.small_title_font_color,
        )
        text = "Summary"
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)

        tStyle = TableStyle(
            [
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                # ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("LINEABOVE", (0, 0), (-1, -1), 1, self.table_line_color),
                ("BACKGROUND", (-2, -1), (-1, -1), self.highlight_color),
            ]
        )

        fontSize = 8

        lineData = []
        total = 0
        for section in self.data:
            if section in [
                "Device Name",
                "Emulator relative action timestamp",
                "Action Duration",
                "Other Data",
                "AI Action Summary",
                "AI Action Overview",
            ]:
                continue
            lineData.append([section, len(self.data[section])])
            total += len(self.data[section])
        for section in self.data["Other Data"]:
            if section in ["Timeline Data"]:
                continue
            if section in ["Artifact Hashes"]:
                len_new = len(
                    self.data["Other Data"]["Artifact Hashes"][0]["new_file_hashes"]
                )
                len_changed = len(
                    self.data["Other Data"]["Artifact Hashes"][0][
                        "changed_file_hashes(old,new)"
                    ]
                )
                lineData.append(["Hashes of files created during action", len_new])
                lineData.append(["Before/after Hashes of changed files", len_changed])
                total += len_new + len_changed
                continue
            lineData.append([section, len(self.data["Other Data"][section][0])])
            total += len(self.data["Other Data"][section][0])
        lineData.append(["Total number of artifacts found", str(total)])

        # for row in lineData:
        #     for item in row:
        #         ptext = "<font size='%s'>%s</font>" % (fontSize-1, item)
        #         p = Paragraph(ptext, centered)
        #         formattedLineData.append(p)
        #     data.append(formattedLineData)
        #     formattedLineData = []

        table = Table(lineData, colWidths=[400, 100])
        table.setStyle(tStyle)
        self.elements.append(table)

        self.elements.append(PageBreak())

    def changedFilesTableMaker(self):
        psHeaderText = ParagraphStyle(
            "Hed0",
            fontSize=12,
            alignment=TA_LEFT,
            borderWidth=3,
            textColor=self.small_title_font_color,
        )
        text = "Changed Files"
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)

        styles = getSampleStyleSheet()
        body_style = styles["BodyText"]
        body_style.alignment = TA_LEFT
        body_style.fontSize = 7

        # Create table headers
        data = [self.make_header(["No.", "File Name", "Changes"])]

        # Populate data from JSON
        lineNum = 1
        for item in self.data["Changed Files"]:
            if isinstance(item, dict):
                # Handle dictionary entries (file name and changes)
                file_name = list(item.keys())[0]
                changes = "\n\n".join(item[file_name])
            else:
                # Handle regular file names
                file_name = item
                changes = ""

            # Create Paragraphs for cell content
            index_cell = Paragraph(str(lineNum), body_style)
            file_name_cell = Paragraph(file_name, body_style)
            changes_cell = Paragraph(Toolbox.truncate(changes), body_style)

            # Add row to data
            data.append([index_cell, file_name_cell, changes_cell])
            lineNum += 1

        # Create table with specified column widths
        table = Table(data, colWidths=[50, 250, 200])

        # Apply table style (similar to other tables)
        tStyle = TableStyle(
            [  # ('GRID',(0, 0), (-1, -1), 0.5, grey),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                # ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("LINEABOVE", (0, 0), (-1, -1), 1, self.table_line_color),
                ("BACKGROUND", (0, 0), (-1, 0), self.table_header_background_color),
                ("SPAN", (0, -1), (-2, -1)),
            ]
        )
        table.setStyle(tStyle)

        # Add table to elements list
        self.elements.append(table)

        # Add page break after the table
        self.elements.append(PageBreak())

    def APKTableMaker(self):
        psHeaderText = ParagraphStyle(
            "Hed0",
            fontSize=12,
            alignment=TA_LEFT,
            borderWidth=3,
            textColor=self.small_title_font_color,
        )
        text = "APKs & Hashes"
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)
        """
        Create the line items
        """
        data = [self.make_header(["No.", "APK", "Hash (md5)"])]
        lineNum = 1
        formattedLineData = []

        alignStyle = [
            ParagraphStyle(name="01", alignment=TA_CENTER),
            ParagraphStyle(name="02", alignment=TA_LEFT),
            ParagraphStyle(name="03", alignment=TA_CENTER),
            ParagraphStyle(name="04", alignment=TA_CENTER),
            ParagraphStyle(name="05", alignment=TA_CENTER),
        ]
        fontSize = 8
        for row in self.data["Other Data"]["APK Hashes"][0]:
            apk, hash = row.split(": ", 1)
            lineData = [str(lineNum), apk, hash]
            # data.append(lineData)
            columnNumber = 0
            for item in lineData:
                ptext = "<font size='%s'>%s</font>" % (fontSize - 1, item)
                p = Paragraph(ptext, alignStyle[columnNumber])
                formattedLineData.append(p)
                columnNumber = columnNumber + 1
            data.append(formattedLineData)
            formattedLineData = []
            lineNum = lineNum + 1

        # print(data)
        table = Table(data, colWidths=[50, 250, 200])
        tStyle = TableStyle(
            [  # ('GRID',(0, 0), (-1, -1), 0.5, grey),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                # ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("LINEABOVE", (0, 0), (-1, -1), 1, self.table_line_color),
                ("BACKGROUND", (0, 0), (-1, 0), self.table_header_background_color),
                ("SPAN", (0, -1), (-2, -1)),
            ]
        )
        table.setStyle(tStyle)
        self.elements.append(table)
        self.elements.append(PageBreak())

    def image_grid(self):
        img_dir = f"{os.getenv('RAW_RESULTS_PATH')}screenshots/"
        img_list = os.listdir(img_dir)
        self.convert_png_to_jpeg(img_list, img_dir)
        img_list = os.listdir(img_dir)

        # Figure out appropriate scaling factors
        img = PILImage.open(img_dir + img_list[0])
        img_width, img_height = img.size
        a4_width, a4_height = A4
        a4_width = a4_width - 1.5 * inch  # margins
        points_per_inch = 72
        dpi = 300
        a4_width_inches = a4_width / points_per_inch
        a4_height_inches = a4_height / points_per_inch
        new_width = a4_width_inches / 4
        scale_factor = new_width / img_width
        new_height = img_height * scale_factor

        # Determine the number of images per row based on the square root of the total number of images
        images_per_row = 4

        # Create a list to hold the rows of images
        image_rows = []

        # Loop through the images, creating a new row for each set of images_per_row images
        for i in range(0, len(img_list), images_per_row):
            # Create a row of images
            image_row = [
                Image(
                    img_dir + img_path, width=new_width * inch, height=new_height * inch
                )
                for img_path in img_list[i : i + images_per_row]
            ]
            # Add the row of images to the list of rows
            image_rows.append(image_row)

        # Create a table with the rows of images
        image_table = Table(image_rows)
        self.elements.append(image_table)

    def convert_png_to_jpeg(self, filenames, img_dir):
        # self.logger.info("Rendering Screenshots into PDF Report, might take some time.")
        for filename in filenames:
            if filename.endswith(".png"):
                img = PILImage.open(img_dir + filename)
                rgb_img = img.convert("RGB")
                jpeg_filename = filename[:-4] + ".jpeg"
                rgb_img.save(img_dir + jpeg_filename, "JPEG", quality=90)
                os.remove(img_dir + filename)  # remove the original PNG file

    def newFileHashesTableMaker(self):
        psHeaderText = ParagraphStyle(
            "Hed0",
            fontSize=12,
            alignment=TA_LEFT,
            borderWidth=3,
            textColor=self.small_title_font_color,
        )
        text = "Hashes of new files"
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)

        styles = getSampleStyleSheet()
        body_style = styles["BodyText"]
        body_style.alignment = TA_LEFT
        body_style.fontSize = 7

        # Initialize data list with headers
        table = [self.make_header(["No.", "File Name", "Hash"])]

        # Populate data from JSON
        # with open('hashes.json', 'r') as f:
        #     json_data = json.load(f)
        #     new_file_hashes = json_data.get("new_file_hashes")

        new_file_hashes = self.data["Other Data"]["Artifact Hashes"][0][
            "new_file_hashes"
        ]

        lineNum = 1
        for file_name, hash in new_file_hashes.items():
            # Create Paragraphs for cell content
            index_cell = Paragraph(str(lineNum), body_style)
            file_name_cell = Paragraph(file_name, body_style)
            hash_cell = Paragraph(hash, body_style)

            # Add row to table
            table.append([index_cell, file_name_cell, hash_cell])
            lineNum += 1

        # Create table with specified column widths
        table = Table(table, colWidths=[50, 250, 200])

        # Apply table style (similar to other tables)
        tStyle = TableStyle(
            [  # ('GRID',(0, 0), (-1, -1), 0.5, grey),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                # ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("LINEABOVE", (0, 0), (-1, -1), 1, self.table_line_color),
                ("BACKGROUND", (0, 0), (-1, 0), self.table_header_background_color),
                ("SPAN", (0, -1), (-2, -1)),
            ]
        )
        table.setStyle(tStyle)

        # Add table to elements list
        self.elements.append(table)

        # Add page break after the table
        self.elements.append(PageBreak())

    def changedFileHashesTableMaker(self):
        psHeaderText = ParagraphStyle(
            "Hed0",
            fontSize=12,
            alignment=TA_LEFT,
            borderWidth=3,
            textColor=self.small_title_font_color,
        )
        text = "Changed File Hashes"
        paragraphReportHeader = Paragraph(text, psHeaderText)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 22)
        self.elements.append(spacer)

        styles = getSampleStyleSheet()
        body_style = styles["BodyText"]
        body_style.alignment = TA_LEFT
        body_style.fontSize = 7

        # Initialize data list with headers
        table = [
            self.make_header(
                ["No.", "File Name", "Hash Before Action", "Hash After Action"]
            )
        ]

        # Populate data from JSON
        # with open('hashes.json', 'r') as f:
        #     json_data = json.load(f)
        #     changed_file_hashes = json_data.get("changed_file_hashes(old,new)")
        changed_file_hashes = self.data["Other Data"]["Artifact Hashes"][0][
            "changed_file_hashes(old,new)"
        ]

        lineNum = 1
        for file_name, hash_list in changed_file_hashes.items():
            # Create Paragraphs for cell content
            index_cell = Paragraph(str(lineNum), body_style)
            file_name_cell = Paragraph(file_name, body_style)
            before_hash_cell = Paragraph(hash_list[0], body_style)
            after_hash_cell = Paragraph(hash_list[1], body_style)

            # Add row to table
            table.append(
                [index_cell, file_name_cell, before_hash_cell, after_hash_cell]
            )
            lineNum += 1

        # Create table with specified column widths
        table = Table(table, colWidths=[25, 245, 115, 115])

        # Apply table style (similar to other tables)
        tStyle = TableStyle(
            [  # ('GRID',(0, 0), (-1, -1), 0.5, grey),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                # ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("LINEABOVE", (0, 0), (-1, -1), 1, self.table_line_color),
                ("BACKGROUND", (0, 0), (-1, 0), self.table_header_background_color),
                ("SPAN", (0, -1), (-2, -1)),
            ]
        )
        table.setStyle(tStyle)

        # Add table to elements list
        self.elements.append(table)

        # Add page break after the table
        self.elements.append(PageBreak())

    def draw_panel(self, x, y, width, height, main_number, title, symbol):
        self.setStrokeColor(self.small_title_font_color)
        self.setFillColor(self.small_title_font_color)  # Light grey fill color
        self.rect(x, y, width, height, fill=1)

        # Draw Main Number
        self.setFont("Helvetica-Bold", 24)
        self.drawCentredString(x + width / 2, y + height / 2 + 10, str(main_number))

        # Draw Title/Description
        self.setFont("Helvetica", 12)
        self.drawCentredString(x + width / 2, y + height - 20, title)

        # Draw Symbol (using text as placeholder for simplicity)
        self.setFont("Helvetica-Bold", 36)
        self.drawCentredString(x + width / 2, y + height / 2 - 30, symbol)

    def make_header(self, header_array):
        result = []
        fontSize = 8
        centered = ParagraphStyle(
            name="centered",
            alignment=TA_CENTER,
            textColor=self.white,
            fontName="Helvetica-Bold",
        )
        for text in header_array:
            ptext = "<font size='%s'><b>%s</b></font>" % (fontSize, text)
            titlesTable = Paragraph(ptext, centered)
            result.append(titlesTable)
        return result


if __name__ == "__main__":
    report = PDFReport(
        "Sandroid_Forensic_Report.pdf", f"{os.getenv('RAW_RESULTS_PATH')}sandroid.json"
    )
