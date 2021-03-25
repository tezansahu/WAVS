const express = require('express');
const hoxy = require('hoxy');
const ejs = require('ejs');

var server_port = 9000;
var proxy_port = 8000;


// Target server (to be implemented in FastAPI)
let app = express();

app.get('/scan', async function(req, res) {
  let query_url = req.query.url;
  console.log("Request received by Virtual Server. Query URL:", query_url);

  res.writeHead(200, {'Content-Type': 'application/json'});
  res.write(JSON.stringify({"url": query_url}));
  res.end();
});

app.listen(server_port, function() {
  console.log('Virtual Server is listening on port', server_port);
});

//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

// Proxy server to direct requests to Virtual Server
var proxy = hoxy.createServer().listen(proxy_port, function() {
  console.log('The Proxy is listening on port', proxy_port, "\n");
});

// Intercept & modify request

// If root path, display landing page template
proxy.intercept({
  phase: 'request',
  url: '/'
}, (req, res) => {
  res.headers = {'Content-Type': 'text/html'};
  res.statusCode = 200;
  res.string = "<html><body><h2>Landing Page!</h2></body></html>";
})

// For all other requests, redirect to virtual server
proxy.intercept({
  phase: 'request'
}, (req, res) => {
  query_url = req.url.slice(1);
  console.log("Request intercepted by proxy. Query URL:", query_url);
  
  // Modify the request to call the required endpoint with correct query param
  req.hostname = 'localhost';         // Domain of Virtual Server
  req.port = server_port;             // Port on which Virtual Server is running
  req.url = '/scan?url=' + query_url  // Appropriate endpoint on Virtual Server
})

//////////////////////////////////////////////////////////////////////////////////////////

// Intercept & modify response
proxy.intercept({
  phase: 'response', 
  as: 'json'
}, async (req, res) => {
  console.log("Response intercepted by proxy:", res.json)

  // Use JSON to manipulate template...
  html_str = await ejs.renderFile("template.ejs", res.json);

  // Now return the filled template
  res.headers = {'Content-Type': 'text/html'};
  res.statusCode = 200;
  res.string = html_str;
  console.log("Modified Response:", res.string, "\n=====================================================")
})
