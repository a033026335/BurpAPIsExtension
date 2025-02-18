
from burp import IBurpExtender, ITab
from javax import swing
from javax.swing import JTabbedPane, ImageIcon, JFrame, JButton, JTextArea, JFileChooser, JPanel, JScrollPane, JLabel, BoxLayout, SwingConstants
from java.awt import Font, BorderLayout
from java.net import URL
from javax.swing import JCheckBox
import json
from urllib import quote, urlencode
from urlparse import urlparse, parse_qs

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

        # Instructions on how to use the extension
        instructionmessage = JLabel(">  This extension aids in adding the names to its corresponding APIs endpoints by parsing endpoint names with corresponding http request of API endpoints in the Repeater Tab.")
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
        self.uploadJsonButton = JButton("Upload JSON and Convert to HTTP", actionPerformed=self.uploadJson)
        buttonPanel.add(self.formatEndpointsButton)
        buttonPanel.add(self.chooseFileButton)
        buttonPanel.add(self.toRepeaterButton)
        buttonPanel.add(self.clearButton)
        buttonPanel.add(self.uploadJsonButton)
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
            # If the external APIs check box is not checked, the formatted endpoint names will only include internal labels, else label internal and external per endpoints. 
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

    def uploadJson(self, event):
        # Create a file chooser
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self.frame)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            with open(file.getAbsolutePath(), 'r') as f:
                data = json.load(f)
                http_requests = self.convert_to_http_requests(data)
                self.textArea.text = "\n".join(http_requests)

    def convert_to_http_requests(self, collection_data, collection_type='postman'):
        http_requests = []
        if collection_type == 'postman':
            for item in collection_data['item']:
                if item.get('request'):
                    method = item['request']['method']
                    url_details = item['request']['url']
                    # Constructing the first line with method and path
                    path = url_details['path']
                    path_str = '/' + '/'.join(path) if path else ''
                    query = '&'.join(['{}={}'.format(q["key"], q["value"]) for q in url_details.get('query', [])])
                    path_with_query = '{}?{}'.format(path_str, query) if query else path_str
                    first_line = '{} {} HTTP/1.1\n'.format(method, path_with_query)
                    # Constructing the headers, including Host and potentially authorization.
                    host = url_details['host']
                    host_str = '.'.join(host) if host else ''
                    headers = item['request'].get('header', [])
                    headers.append({'key': 'Host', 'value': host_str})  # Add Host header
                    # Adding scanning for Content-Type header as part of header to make sure it has required Content-Type parameter.
                    content_type_present = any(header.get('key','') == 'Content-Type' for header in headers)
                    if not content_type_present:
                        headers.append({'key':'Content-Type', 'value': 'application/json'})
                    # Check for auth object and append auth header accordingly and add it into header.
                    auth = item['request'].get('auth')
                    if auth:
                        if auth['type'] == 'basic':
                            import base64
                            user_pass = "{}:{}".format(auth['basic'][0]['value'], auth['basic'][1]['value'])
                            encoded_credentials = base64.b64encode(user_pass.encode()).decode()
                            headers.append({'key': 'Authorization', 'value': 'Basic {}'.format(encoded_credentials)})
                        elif auth['type'] == 'bearer':
                            token = auth['bearer'][0]['value']
                            headers.append({'key': 'Authorization', 'value': 'Bearer {}'.format(token)})
                        # Add other auth types here as needed
                    headers_line = '\n'.join(['{}: {}'.format(header["key"], header["value"]) for header in headers]) + '\n\n'
                    # Constructing the body from the 'raw' parameter
                    body = item['request'].get('body', {})
                    body_line = body.get('raw', '') + '\n\n' if body.get('mode') == 'raw' else ''
                    http_requests.append(first_line + headers_line + body_line)

        elif collection_type == 'insomnia':
            for item in collection_data.get('resources', []):
                if item.get('_type') == 'request':
                    method = item.get('method')
                    url = item.get('url')
                    parsed_url = urlparse(url)
                    # Handle merging existing and new query parameters
                    existing_query = parse_qs(parsed_url.query)
                    params = item.get('parameters', [])
                    param_dict = {param['name']: param['value'] for param in params if 'name' in param and 'value' in param}
                    all_params = {**existing_query, **param_dict}
                    full_query = urlencode(all_params, doseq=True)
                    path_with_query = parsed_url.path
                    if full_query:
                        path_with_query += '?{}'.format(full_query)
                    first_line = '{} {} HTTP/1.1\n'.format(method, path_with_query)
                    headers = item.get('headers', [])
                    headers.append({'name': 'Host', 'value': parsed_url.netloc})
                    # Adding scanning for Content-Type header as part of header to make sure it has required Content-Type parameter.
                    content_type_present = any(header.get('name','') == 'Content-Type' for header in headers)
                    if not content_type_present:
                        headers.append({'name':'Content-Type', 'value': 'application/json'})
                    auth = item.get('authentication', {})
                    auth_type = auth.get('type')
                    if auth_type == 'basic':
                        import base64
                        user_pass = "{}:{}".format(auth.get('username'), auth.get('password'))
                        encoded_credentials = base64.b64encode(user_pass.encode()).decode()
                        headers.append({'name': 'Authorization', 'value': 'Basic {}'.format(encoded_credentials)})
                    elif auth_type == 'bearer':
                        token = auth.get('token')
                        headers.append({'name': 'Authorization', 'value': 'Bearer {}'.format(token)})
                    headers_line = '\n'.join(['{}: {}'.format(header["name"], header["value"]) for header in headers]) + '\n\n'
                    body = item.get('body', {})
                    body_type = body.get('mimeType')
                    body_content = body.get('text', '')
                    body_line = body_content + '\n\n'  # Default fallback
                    if body_content and body_type == 'application/json':
                        try:
                            json_object = json.loads(body_content)
                            body_line = json.dumps(json_object, indent=2) + '\n\n'
                        except json.JSONDecodeError:
                            print("Error decoding JSON: Invalid content")  # Logging the error
                            body_line = 'Invalid JSON content.\n\n'
                    elif body_type == 'application/x-www-form-urlencoded':
                        try:
                            body_line = urlencode(json.loads(body_content)) + '\n\n'
                        except json.JSONDecodeError:
                            print("Error decoding form-urlencoded data: Invalid content")
                            body_line = 'Invalid form data.\n\n'
                    http_requests.append(first_line + headers_line + body_line)
        return http_requests
