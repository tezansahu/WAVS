const express = require('express');
var path = require('path');
const ejs = require('ejs')

var server_port = process.env.PORT || 8080;


let app = express();
app.set('view engine', 'ejs');

app.get('/', function(req, res) {
    let query_url = req.query.url;
    if (query_url != null) {
        if (!query_url.startsWith("http://") && !query_url.startsWith("https://")) {
            query_url = "https://" + query_url;
        }
        console.log("Redirect Query URL:", query_url);
        res.redirect(query_url);
    }
    else {
        // res.sendFile(path.join(__dirname, "index.html"));
        res.render("index", {})
    }
});

app.get('/search', function(req, res) {
    let query = req.query.query;
    if (query != null) {
        message = "Sorry, no results were found for <b>" + query + "</b>."
        message += " <a href='?'>Try again</a>."
        res.render("index", {"search_res": message})
    }
    else {
        res.render("index", {})
    }
});

app.listen(server_port, function() {
  console.log('Virtual Server is listening on port', server_port);
});