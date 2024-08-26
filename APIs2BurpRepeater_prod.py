#The purpose of this extension is to help pen testers to easily import http requests
#with all sizes and have it import directly into Burp Suite Repeater tab.
#This will help pen testers save a lot of time when there are large amount of API endpoints that are in scope,
#by helping pen tester naming tab with approperiate endpoints, and to prevent sending individual call to the Repeater tab.

from burp import IBurpExtender, ITab
from javax import swing
from javax.swing import JTabbedPane, ImageIcon, JFrame, JButton, JTextArea, JFileChooser, JPanel, JScrollPane, JLabel, BoxLayout, SwingConstants
from java.awt import Font, BorderLayout
from java.net import URL
from javax.swing import JCheckBox

class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):

        # Set up the extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("APIs2BurpRepeater")
        callbacks.issueAlert("APIs2BurpRepeater")

        # Create GUI
        self.frame = JFrame("APIs2BurpRepeater")
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        # Welcome label at the top
        welcomeLabel = JLabel("Welcome to APIs2BurpRepeater Extension", SwingConstants.LEFT)
        welcomeLabel.setFont(Font("SansSerif", Font.BOLD, 25))
        self.panel.add(welcomeLabel, BorderLayout.PAGE_START)

        #Instructions on how to use the extension
        instructionmessage = JLabel(">  This extension aids in adding the names to its corresponding APIs endpoints by parsing endpoint names with corrosponding http request of API endpoints in the Repeater Tab.")
        self.panel.add(instructionmessage, BorderLayout.CENTER)
        instructionmessage.setFont(Font("SansSerif",Font.PLAIN,14))
        instructionmessage9 = JLabel("      Follow the instructions below to Format Endpoint Names, Import HTTP requests via .txt file, and combine both data sets to send to Repeater Tab. ")
        self.panel.add(instructionmessage9, BorderLayout.CENTER)
        instructionmessage9.setFont(Font("SansSerif",Font.PLAIN,14))
        instructionmessage8 = JLabel("   ")
        self.panel.add(instructionmessage8, BorderLayout.CENTER)
        instructionmessage1 = JLabel("1: In the Top Text Area box, enter the endpoint names in a list format according to how they are listed in the file of endpoints.")
        self.panel.add(instructionmessage1, BorderLayout.CENTER)
        instructionmessage1.setFont(Font("SansSerif",Font.PLAIN,14))
        instructionmessage3 = JLabel("     If there are external APIs, make sure to check the box that says, External APIs.  Then hit Format Endpoint Names.")
        self.panel.add(instructionmessage3, BorderLayout.CENTER)
        instructionmessage3.setFont(Font("SansSerif",Font.PLAIN,14))
        instructionmessage.setFont(Font("SansSerif",Font.PLAIN,14))
        instructionmessage8 = JLabel("   ")
        self.panel.add(instructionmessage8, BorderLayout.CENTER)
        instructionmessage5 = JLabel("2: Hit the Clear Top Text Area button.")
        self.panel.add(instructionmessage5, BorderLayout.CENTER)
        instructionmessage5.setFont(Font("SansSerif",Font.PLAIN,14))
        instructionmessage8 = JLabel("   ")
        self.panel.add(instructionmessage8, BorderLayout.CENTER)
        instructionmessage6 = JLabel("3: Hit the Import HTTP requests .txt File button. Select the file that contains all HTTP requests in the same order as the endpoint names list from Step 1.")
        self.panel.add(instructionmessage6, BorderLayout.CENTER)
        instructionmessage6.setFont(Font("SansSerif",Font.PLAIN,14))
        instructionmessage.setFont(Font("SansSerif",Font.PLAIN,14))
        instructionmessage8 = JLabel("   ")
        self.panel.add(instructionmessage8, BorderLayout.CENTER)
        instructionmessage7 = JLabel("4: Hit the Send to Repeater Tab button.  All HTTP requests will be formatted according to the list and the file that was imported. ")
        self.panel.add(instructionmessage7, BorderLayout.CENTER)
        instructionmessage7.setFont(Font("SansSerif",Font.PLAIN,14))
        instructionmessage8 = JLabel("   ")
        self.panel.add(instructionmessage8, BorderLayout.CENTER)

        # Buttons at the top center
        buttonPanel = JPanel()

        # Checkbox for external APIs
        self.externalApiCheckbox = JCheckBox("External APIs")
        self.panel.add(self.externalApiCheckbox, BorderLayout.NORTH)

        # Functional buttons for different actions.
        self.formatEndpointsButton = JButton("Format Endpoint Names", actionPerformed=self.formatEndpoints)
        self.chooseFileButton = JButton("Import HTTP requests .txt File", actionPerformed=self.chooseFile)
        self.toRepeaterButton = JButton("Send to Repeater Tab", actionPerformed=self.sendToRepeater)
        self.clearButton = JButton("Clear Top Text Area", actionPerformed=self.clearText)
        buttonPanel.add(self.formatEndpointsButton)
        buttonPanel.add(self.chooseFileButton)
        buttonPanel.add(self.toRepeaterButton)
        buttonPanel.add(self.clearButton)
        self.panel.add(buttonPanel, BorderLayout.NORTH)

        # Text area for displaying imported requests named "textArea"
        self.textArea = JTextArea(10, 50)
        self.scrollPane = JScrollPane(self.textArea)
        toptextArea = swing.JLabel("Top Text Area:")
        self.panel.add(toptextArea,  BorderLayout.CENTER)
        self.panel.add(self.scrollPane,  BorderLayout.CENTER)

        # Second text area for displaying formatted endpoints named "endpointsTextArea"
        self.endpointsTextArea = JTextArea(10, 50)
        self.endpointsScrollPane = JScrollPane(self.endpointsTextArea)
        bottomtextArea = swing.JLabel("Bottom Text Area:")
        self.panel.add(bottomtextArea, BorderLayout.CENTER)
        self.panel.add(self.endpointsScrollPane, BorderLayout.CENTER)
        self.frame.getContentPane().add(self.panel)
        
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "APIs2BurpRepeater"
    
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
        # Check if External APIs checkbox is checked
        isExternal = self.externalApiCheckbox.isSelected()
        # Process and format pasted endpoint names
        rawEndpoints = self.textArea.text.split("\n")
        formattedEndpoints = []
        for endpoint in rawEndpoints:
            endpoint = endpoint.strip()
            # If the external APIs check box is not checked, the formated endpoint names will only include internal labels, else label internal and external per endpoints. 
            if endpoint:
                if isExternal:
                    formattedEndpoint = "internal-" + endpoint + ", external-" + endpoint
                else:
                    formattedEndpoint = "internal-" + endpoint
                formattedEndpoints.append(formattedEndpoint)
        formattedEndpointsString = "#Endpoints:[" + ", ".join(formattedEndpoints) + "]"
        self.endpointsTextArea.setText(formattedEndpointsString)

    def sendToRepeater(self, e):
        # Process requests
        lines = self.textArea.text.split("\n")
        # Filter out the #Endpoints line
        lines = [line for line in lines if not line.startswith("#Endpoints")]
        requests = []
        self.endpointNames = self.processEndpoints(self.endpointsTextArea.text)
        currentRequest = []
        endpointIndex = 0  # Index to track the current endpoint
        for line in lines:
            if line.split(" ")[0].upper() in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTION", "HEAD", "UPDATE"]:
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
        default_protocol = "https"
        port = 443  # Default HTTP port
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
