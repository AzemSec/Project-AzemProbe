import sys
import socket
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QRadioButton,
    QTextEdit, QProgressBar, QButtonGroup, QFileDialog, QMessageBox, QVBoxLayout, QWidget
)
from PyQt5.QtCore import Qt

class PortScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("AzemProbe")
        self.setGeometry(200, 200, 800, 600)
        self.init_ui()

    def init_ui(self):
        #Layout
        layout = QVBoxLayout()

        #Target Input
        self.target_label = QLabel("Target (IP or hostname):")
        layout.addWidget(self.target_label)

        self.target_input = QLineEdit(self)
        self.target_input.setPlaceholderText("Enter target IP or hostname")
        layout.addWidget(self.target_input)

        #Scan Mode Selection
        self.scan_mode_label = QLabel("Select Scan Mode:")
        layout.addWidget(self.scan_mode_label)

        self.quick_scan_radio = QRadioButton("Quick Scan (1-1024)", self)
        self.full_scan_radio = QRadioButton("Full Scan (1-65535)", self)
        self.custom_scan_radio = QRadioButton("Custom Scan (specify range)", self)

        layout.addWidget(self.quick_scan_radio)
        layout.addWidget(self.full_scan_radio)
        layout.addWidget(self.custom_scan_radio)

        #Button group for radio buttons
        self.scan_mode_group = QButtonGroup()
        self.scan_mode_group.addButton(self.quick_scan_radio)
        self.scan_mode_group.addButton(self.full_scan_radio)
        self.scan_mode_group.addButton(self.custom_scan_radio)

        #Custom Port Range Input
        self.custom_ports_label = QLabel("Custom Port Range (start-end):")
        layout.addWidget(self.custom_ports_label)

        self.custom_ports_input = QLineEdit(self)
        self.custom_ports_input.setPlaceholderText("e.g., 1000-2000")
        layout.addWidget(self.custom_ports_input)
        self.custom_ports_input.setEnabled(False)  # Disabled by default

        self.custom_scan_radio.toggled.connect(self.toggle_custom_ports_input)

        #Start Scan Button
        self.start_scan_button = QPushButton("Start Scan", self)
        self.start_scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.start_scan_button)

        #Progress Bar
        self.progress_bar = QProgressBar(self)
        layout.addWidget(self.progress_bar)

        #Results Text Area
        self.result_text = QTextEdit(self)
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)

        #Save Results Button
        self.save_button = QPushButton("Save Results", self)
        self.save_button.clicked.connect(self.save_results)
        layout.addWidget(self.save_button)

        #Main Widget
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def toggle_custom_ports_input(self):
        """Enable or disable the custom ports input field based on the selected scan mode."""
        self.custom_ports_input.setEnabled(self.custom_scan_radio.isChecked())

    def start_scan(self):
        """Start the port scanning process."""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Invalid Target", "Please enter a valid target.")
            return

        #Determine scan mode and ports
        if self.quick_scan_radio.isChecked():
            ports = range(1, 1025)
        elif self.full_scan_radio.isChecked():
            ports = range(1, 65536)
        elif self.custom_scan_radio.isChecked():
            port_range = self.custom_ports_input.text().strip()
            try:
                start_port, end_port = map(int, port_range.split("-"))
                ports = range(start_port, end_port + 1)
            except ValueError:
                QMessageBox.warning(self, "Input Error", "Invalid port range. Use format: start-end")
                return
        else:
            QMessageBox.warning(self, "Input Error", "Please select a scan mode.")
            return

        self.result_text.clear()
        self.progress_bar.setValue(0)

        #Start scanning in a separate thread to keep the UI responsive
        threading.Thread(target=self.port_scan, args=(target, ports), daemon=True).start()

    def port_scan(self, target, ports):
        """Perform the port scan."""
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.result_text.append(f"Invalid target: {target}")
            return

        self.result_text.append(f"Scanning target: {target_ip}\n")
        total_ports = len(ports)
        scanned_ports = 0

        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)  # Set timeout for connection attempt
                    result = s.connect_ex((target_ip, port))
                    if result == 0:
                        self.result_text.append(f"Port {port} is open")
            except Exception as e:
                self.result_text.append(f"Error scanning port {port}: {e}")
            finally:
                scanned_ports += 1
                progress = int((scanned_ports / total_ports) * 100)
                self.progress_bar.setValue(progress)

        self.result_text.append("\nScan completed.")
        QMessageBox.information(self, "Scan Complete", "Port scanning is finished!")

    def save_results(self):
        """Save the scan results to a file."""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "Text Files (*.txt)")
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.result_text.toPlainText())
            QMessageBox.information(self, "Success", f"Results saved to {file_path}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = PortScannerApp()
    scanner.show()
    sys.exit(app.exec_())
