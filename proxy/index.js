const hoxy = require('hoxy');
const ejs = require('ejs');
const fs = require('fs');
const { program } = require('commander');

program
  .option('-s, --scan <type>', 'Scan Type ("full" or "selective")', 'full')
  .option('-t, --tls_cert', 'Enable scan for SSL/TLS Certificates')
  .option('-x, --xss', 'Enable scan for Cross-Site Scripting')
  .option('-p, --phishing', 'Enable scan for potential Phishing')
  .option('-o, --open_redirect', 'Enable scan for Open Redirects')  

program.parse(process.argv);
const options = program.opts();

scan_options = {
  tls_cert: false,
  xss: false,
  phishing: false,
  open_redirect: false
};

if (options.scan === 'full') {
  scan_options = {
    tls_cert: true,
    xss: true,
    phishing: true,
    open_redirect: true
  }
}
else if (options.scan === 'selective') {
  if (options.tls_cert) {
    scan_options["tls_cert"] = true;
  }
  if (options.xss) {
    scan_options["xss"] = true;
  }
  if (options.phishing) {
    scan_options["phishing"] = true;
  }
  if (options.open_redirect) {
    scan_options["open_redirect"] = true;
  }
}


homepage_str = "";

fs.readFile("./templates/homepage.html", (error, data) => {
  if(error) {
      throw error;
  }
  homepage_str = data.toString();
});

var server_port = 9000;
var proxy_port = 8000;


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
  // res.string = "<html><body><h2>Landing Page!</h2></body></html>";
  res.string = homepage_str;
})

// For all other requests, redirect to virtual server
proxy.intercept({
  phase: 'request'
}, (req, res) => {
  query_url = req.url.slice(1);
  
  // Modify the request to call the required endpoint with correct query param
  req.method = 'POST';
  req.hostname = 'localhost';         // Domain of Virtual Server
  req.port = server_port;             // Port on which Virtual Server is running
  req.url = '/v1/scan/?url=' + query_url  // Appropriate endpoint on Virtual Server
  req.json = scan_options
})

//////////////////////////////////////////////////////////////////////////////////////////

// Intercept & modify response
proxy.intercept({
  phase: 'response', 
  as: 'json'
}, async (req, res) => {
  // console.log("Response intercepted by proxy:", res.json)

  // Use JSON to manipulate template...
  html_str = await ejs.renderFile("templates/dashboard.ejs", res.json);

  // Now return the filled template
  res.headers = {'Content-Type': 'text/html'};
  res.statusCode = 200;
  res.string = html_str;
  // console.log("Modified Response:", res.string, "\n=====================================================")
})
