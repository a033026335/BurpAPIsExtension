#The purpose of this extension is to help pen testers to easily import Postman collections,
#or cURL commands with all sizes from remediation lead and have it import directly into Burp Suite Repeater tab.
#This will help pen testers save a lot of time when there are large amount of API endpoints that are in scope,
#by helping pen tester naming tab with approperiate endpoints, and to prevent sending individual call to the Repeater tab.

from burp import IBurpExtender, ITab
from javax.swing import JFrame, JButton, JTextArea, JFileChooser, JPanel, JScrollPane, JLabel, BoxLayout
from java.awt import Font, BorderLayout
from java.net import URL
class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        # Set up the extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HTTP Requests Importer")
        callbacks.issueAlert("HTTP Request Importer Loaded")
        # Create GUI
        self.frame = JFrame("Import HTTP Requests")
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        # Welcome label at the top
        welcomeLabel = JLabel("Welcome to HTTP Requests Importer")
        welcomeLabel.setFont(Font("SansSerif", Font.BOLD, 30))
        self.panel.add(welcomeLabel, BorderLayout.NORTH)

        instructionmessage = JLabel("Please follow the following instruction to import http requests and sent to Repeater Tab.")
        self.panel.add(instructionmessage, BorderLayout.WEST)
        instructionmessage1 = JLabel("First: You would want to process and formate your list of endpoint names for all of your HTTP requests.")
        self.panel.add(instructionmessage1, BorderLayout.WEST)

        # Buttons at the top center
        buttonPanel = JPanel()
        self.formatEndpointsButton = JButton("Format Endpoint Names", actionPerformed=self.formatEndpoints)
        self.chooseFileButton = JButton("Import HTTP requests .txt File", actionPerformed=self.chooseFile)
        self.toRepeaterButton = JButton("Send to Repeater Tab", actionPerformed=self.sendToRepeater)
        self.clearButton = JButton("Clear Imported HTTP Requests", actionPerformed=self.clearText)
        buttonPanel.add(self.formatEndpointsButton)
        buttonPanel.add(self.chooseFileButton)
        buttonPanel.add(self.toRepeaterButton)
        buttonPanel.add(self.clearButton)
        self.panel.add(buttonPanel, BorderLayout.NORTH)
        # Text area for displaying imported requests
        self.textArea = JTextArea(10, 50)
        self.scrollPane = JScrollPane(self.textArea)
        self.panel.add(self.scrollPane, BorderLayout.CENTER)
        # Second text area for displaying formatted endpoints
        self.endpointsTextArea = JTextArea(10, 50)
        self.endpointsScrollPane = JScrollPane(self.endpointsTextArea)
        self.panel.add(self.endpointsScrollPane, BorderLayout.CENTER)
        self.frame.getContentPane().add(self.panel)
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "HTTP Request Importer"
    
    def getUiComponent(self):
        return self.panel
    
    def clearText(self, event):
        # Clear the text area
        self.textArea.setText("")

    def chooseFile(self, e):
        # Create a file chooser
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self.frame)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            with open(file.getAbsolutePath(), 'r') as f:
                file_contents = f.readlines()
                # Extract endpoint names from the last line
                if file_contents and file_contents[-1].startswith("#Endpoints:"):
                    self.endpointNames = file_contents[-1].strip().split(":")[1].strip("[]").split(", ")
                    # Remove the last line (endpoints list) from the file contents
                    file_contents = file_contents[:-1]
                else:
                    self.endpointNames = []
                # Set the text area with the remaining file contents
                self.textArea.text = "".join(file_contents)

    def formatEndpoints(self, event):
        # Process and format pasted endpoint names
        rawEndpoints = self.textArea.text.split("\n")
        formattedEndpoints = [endpoint.strip() for endpoint in rawEndpoints if endpoint.strip()]
        formattedEndpointsString = "#Endpoints:[" + ", ".join(formattedEndpoints) + "]"
        self.endpointsTextArea.setText(formattedEndpointsString)

    def sendToRepeater(self, e):
        # Process requests
        lines = self.textArea.text.split("\n")
        requests = []
        self.endpointNames = self.processEndpoints(self.endpointsTextArea.text)
        currentRequest = []
        endpointIndex = 0  # Index to track the current endpoint
        for line in lines:
            if line.split(" ")[0].upper() in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTION", "HEAD"]:
                if currentRequest:
                    requests.append("\n".join(currentRequest))
                    currentRequest = []
            currentRequest.append(line)
        if currentRequest:
            requests.append("\n".join(currentRequest))
        for request in requests:
            try:
                # Get the endpoint name using the index, if available
                endpointName = self.endpointNames[endpointIndex] if endpointIndex < len(self.endpointNames) else "Default"
                self.parseAndSendRequest(request, endpointName)
                endpointIndex += 1
            except Exception as ex:
                print("Error processing request: ", ex)
    def processEndpoints(self, endpointsText):
        if endpointsText.startswith("#Endpoints:"):
            return endpointsText.strip().split(":")[1].strip("[]").split(", ")
        else:
            return []
        
    def parseAndSendRequest(self, request, endpointName):
        # Default to HTTP
        default_protocol = "http"
        port = 80  # Default HTTP port
        # Extract the host, protocol, and port
        lines = request.split("\n")
        first_line = lines[0].split(" ")
        method, path = first_line[0], first_line[1]
        # Try to find the Host header in the request
        host_header = self.findHostHeader(lines)
        host = host_header if host_header else "example.com"  # Default host if no Host header is found
        # Check if the URL is complete
        if path.startswith("http://") or path.startswith("https://"):
            url = URL(path)
            protocol = url.getProtocol()
            host = url.getHost() if not host_header else host  # Use host from URL only if no Host header
            port =url.getPort() if url.getPort() > -1 else (80 if protocol == "http" else 443)
        else:
            # Use the extracted host if the path is not a full URL
            protocol = default_protocol
            path = protocol + "://" + host + path
            # Convert the request to a byte array
            request_bytes = self._helpers.stringToBytes(request)
            # Build and send the HTTP service
            httpService = self._helpers.buildHttpService(host, port, default_protocol)
            self._callbacks.sendToRepeater(httpService.getHost(), httpService.getPort(), httpService.getProtocol() == "https", request_bytes, endpointName)

    def findHostHeader(self, lines):
        for line in lines:
            if line.lower().startswith("host:"):
                return line.split(" ")[1].strip()
        return None