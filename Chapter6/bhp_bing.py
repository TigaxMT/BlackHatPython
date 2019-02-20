from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import socket
import urllib
import json
import re
import base64
import threading

bing_api_key = "My Subscription Key"
bing_api_host = "api.cognitive.microsoft.com"
bing_api_urlquery = "https://api.cognitive.microsoft.com/bing/v7.0/search?count=20&q="


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None 

        # we set up our extension

        callbacks.setExtensionName("BHP Bing")
        callbacks.registerContextMenuFactory(self)

        return 
    
    def createMenuItems(self, context_menu):

        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to Bing", actionPerformed=self.bing_menu))

        return menu_list
    
    def bing_menu(self, event):

        # grab the details of what the user clicked
        http_traffic = self.context.getSelectedMessages()

        print("%d requests highlighted" % len(http_traffic))

        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()

            print("User selected host: %s" % host)

            self.bing_search(host)
        
        return 
    
    def bing_search(self, host):

        # check if we habe an IP or hostname
        is_ip = re.match("[0-9]+(?:\.[0-9]+){3}", host)

        if is_ip:
            ip_adress = host
            domain = False 
        else:
            ip_adress = socket.gethostbyname(host)
            domain = True 

        # Here we need to use threading to create threads to call bing_query()
        # All of this because if we don't thread, the call will execute inside of Swing (client-side)
        # breaking all UI until the request to bing happen
        if domain:
            bing_query_string = "'domain:%s'" % host 
            t1 = threading.Thread(target=self.bing_query, args=(bing_query_string,))
            t1.start()
        
        else:
            bing_query_string = "'ip:%s'" % host
            t2 = threading.Thread(target=self.bing_query, args=(bing_query_string,))
            t2.start()
        
    
    def bing_query(self, bing_query_string):

        print("Performing Bing search: %s" % bing_query_string)

        # encode our query
        quoted_query = urllib.quote(bing_query_string)

        # the query is different too using the Bing Search Engine V7
        http_request = "GET %s%s HTTP/1.1\r\n" % (bing_api_urlquery, quoted_query)
        
        # The host instead of the older api.marketplace, now we use the api.cognitive
        http_request += "Host: %s\r\n" % bing_api_host

        http_request += "Connection: close\r\n"
        
        # Now we don't use Basic Auth we need to pass the subscription key(API key)
        http_request += "Ocp-Apim-Subscription-Key: %s\r\n" % bing_api_key

        http_request += "User-Agent: Blackhat Python\r\n\r\n"
        
        json_body = self._callbacks.makeHttpRequest(bing_api_host, 443, True, http_request).tostring()
        
        json_body = json_body.split("\r\n\r\n",1)[1]

        try:

            r = json.loads(json_body)
            
            if len(r["webPages"]["value"]):

                for site in r["webPages"]["value"]:
                    
                    print("*"*100)
                    print(site['name'])
                    print(site['url'])
                    print(site['snippet'])
                    print("*"*100)

                    j_url = URL(site['url'])

                    if not self._callbacks.isInScope(j_url):
                        print("Adding to Burp Scope")
                        self._callbacks.includeInScope(j_url)

        except:
            print("No results from Bing")
            pass
        
        return
