const config = require('./config');
const fs = require('fs');
const https = require('https'); 
const async = require('async');
const errorhandler = require('errorhandler');
var proxy = require('express-http-proxy');
var saml2 = require('./lib/saml2.js');
var bodyParser = require('body-parser');
var qs = require('querystring');
var xmldom = require('xmldom');

config.azf = config.azf || {};
config.https = config.https || {};

const log = require('./lib/logger').logger.getLogger("Server");

const express = require('express');

process.on('uncaughtException', function (err) {
  log.error('Caught exception: ' + err);
});
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const app = express();

app.use(errorhandler({log: log.error}));

let port = config.listen_port || 80;
if (config.https.enabled) {port = config.https.port || 443;}
app.set('port', port);


// Create service provider
var sp_options = {
    entity_id: "",
    private_key: fs.readFileSync("cert/node-key.pem").toString(),
    certificate: '',
    assert_endpoint: '',
    audience: '',
    sign_get_request: true,
    nameid_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    provider_name: '',
    auth_context: { comparison: "minimum", AuthnContextClassRef: ["http://eidas.europa.eu/LoA/low"] },
    force_authn: true,
    organization: '',
    contact: '',
    valid_until: '',
    sp_type: ''
};

// Create identity provider
var idp_options = {
  sso_login_url: '',
  sso_logout_url: "",
  certificates: []
};
var idp = new saml2.IdentityProvider(idp_options);

var sp = new saml2.ServiceProvider(sp_options);

XMLNS = {
  SAML: 'urn:oasis:names:tc:SAML:2.0:assertion',
  SAMLP: 'urn:oasis:names:tc:SAML:2.0:protocol',
  MD: 'urn:oasis:names:tc:SAML:2.0:metadata',
  DS: 'http://www.w3.org/2000/09/xmldsig#',
  XENC: 'http://www.w3.org/2001/04/xmlenc#',
  EXC_C14N: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  EIDAS: 'http://eidas.europa.eu/saml-extensions'
};

//{id: [list of attributes]}
var attributes_map = {};

app.use ('/', proxy(config.eidas_node, {
    proxyReqBodyDecorator: function(proxyReq, srcReq) {
        return new Promise(function(resolve, reject) {

            if (srcReq.originalUrl === '/IdP/AuthenticateCitizen') {
                console.log('**************************IDAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
                var json = qs.parse(proxyReq.toString('utf8'));
                var samlreq = json.SAMLRequest;
                var buff = new Buffer(samlreq, 'base64');  
                var text = buff.toString('utf8');
                var xml = new xmldom.DOMParser().parseFromString(text);
                var request_element = xml.getElementsByTagNameNS(XMLNS.SAMLP, 'AuthnRequest')[0];
                var request_id = request_element.getAttribute('ID');
                console.log('Request ID: ', request_id);
                var extensions_element = request_element.getElementsByTagNameNS(XMLNS.SAMLP, 'Extensions')[0];
                var requested_attributes = extensions_element.getElementsByTagNameNS(XMLNS.EIDAS, 'RequestedAttributes')[0];
                var attributes = requested_attributes.getElementsByTagNameNS(XMLNS.EIDAS, 'RequestedAttribute');
                console.log('Requested Attributes', attributes.length);

                attributes_map[request_id] = [];

                for (var i = 0; i < attributes.length; i++) {
                    console.log('Attribute ', attributes[i].getAttribute('FriendlyName'));
                    attributes_map[request_id].push(attributes[i].getAttribute('FriendlyName'));
                }
                console.log('Requested Attributes Map', attributes_map);

                resolve(proxyReq);
            } else if (srcReq.originalUrl === '/EidasNode/IdpResponse') {
                console.log('**************************VUELTAAAAAAAAAAAAAAAAAAAAAAAAAAA');
                var json = qs.parse(proxyReq.toString('utf8'));
                // console.log('Body', json);
                var options = {request_body: json};
                sp.post_assert(idp, options, function(err, saml_response) {
                    if (err != null) {
                        console.log('ERROR', err);
                            
                    } else {


                        var samlres = json.SAMLResponse;
                        var buff = new Buffer(samlres, 'base64');  
                        var text = buff.toString('utf8');
                        var xml = new xmldom.DOMParser().parseFromString(text);
                        var response_element = xml.getElementsByTagNameNS(XMLNS.SAMLP, 'Response')[0];
                        var response_to = response_element.getAttribute('InResponseTo');
                        console.log('Requested Attributes Map', attributes_map);
                        console.log('In response to', response_to);

                        console.log('Requested attributes: ', attributes_map[response_to]);




                        var dom = saml_response.decrypted;
                        var ser = new xmldom.XMLSerializer().serializeToString(dom);
                        var assertion_element = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')[0];
                        var attributeStatement = assertion_element.getElementsByTagNameNS(XMLNS.SAML, 'AttributeStatement')[0];
                        console.log('string', attributeStatement);
                        var new_element = new xmldom.DOMParser().parseFromString('<saml2:Attribute FriendlyName="PEPE" Name="http://eidas.europa.eu/attributes/naturalperson/PEPE" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="eidas-natural:PEPE">PEPEITO</saml2:AttributeValue></saml2:Attribute>');  

                        attributeStatement.appendChild(new_element);

                        // console.log('string nuevo', new xmldom.XMLSerializer().serializeToString(dom));

                        resolve(proxyReq);
                    }
                });
            } else {
                resolve(proxyReq);
            }
        });
    }
}));

if (config.https.enabled === true) {
    const options = {
        key: fs.readFileSync(config.https.key_file),
        cert: fs.readFileSync(config.https.cert_file)
    };

    https.createServer(options, function(req,res) {
        app.handle(req, res);
    }).listen(app.get('port'));
} else {
    app.listen(app.get('port'));
}
