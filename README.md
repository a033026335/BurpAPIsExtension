# BurpAPIsExtension

<img width="1020" alt="image" src="https://github.com/a033026335/BurpAPIsExtension/assets/35503874/4af7d2b9-9fe4-459b-82ef-ba1f568cfb52">

Burp Extension to parse HTTP requests for APIs to Repeater tabs with formatted tab names.

Download
The plugin can be downloaded from the releases tab and loaded into Burp under the Extender tab.

Usage

1: You would want to process and format your list of endpoint names for all of your HTTP requests.
If the solution contains external proxies, make sure to check the check box that says external APIs. Then click formate endpoint names.
You then will have formatted endpoint names in the order of the questionnaire at the bottom text box that will be utilized by the repeater tab.

2: you will go ahead and click the clear top text box button to clear pasted endpoint names, then click the import HTTP requests .txt file button.
Select the file that contains all HTTP requests that are in the corresponding order with the formatted endpoint names.

3: you can just click the send to repeater tab button. Then all HTTP requests should have the corresponding endpoint name in the order in which it was imported.")

Note:

There is an additional Python script that you can download where users can upload Postman or Insomnia collections and format HTTP requests and scoped endpoints as output. Please see the following GitHub page for Parse_scope.
