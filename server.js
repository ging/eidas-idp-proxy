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

app.use(bodyParser.json());
app.use(bodyParser.urlencoded());

app.use(errorhandler({log: log.error}));

let port = config.listen_port || 80;
if (config.https.enabled) {port = config.https.port || 443;}
app.set('port', port);


// Create service provider
var sp_options = {
    entity_id: "https://"+config.eidas_node,
    private_key: fs.readFileSync("cert/mashmetv-key.pem").toString(),
    certificate: fs.readFileSync("cert/mashmetv-cert.pem").toString(),
    assert_endpoint: "https://"+config.eidas_node,
    audience: "https://"+config.eidas_node,
    sign_get_request: true,
    nameid_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    provider_name: '344r3f3234234',
    auth_context: { comparison: "minimum", AuthnContextClassRef: ["http://eidas.europa.eu/LoA/low"] },
    force_authn: true,
    organization: '',
    contact: '',
    valid_until: new Date(),
    sp_type: 'public'
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

// Create service provider
var ap_connector_options = {
    entity_id: "https://se-eidas.redsara.es/IdP/Metadata",
    destination: "https://se-eidas.redsara.es/EidasNode/IdpResponse",
    rsa_pub: fs.readFileSync("cert/pubkey.pem").toString(),
    private_key: fs.readFileSync("cert/mashmetv-key.pem").toString(),
    certificate: fs.readFileSync("cert/mashmetv-cert.pem").toString(),
    sign_get_request: true,
    encrypt_request: true,
    inResponseTo: 'aaaaaaa' //ID_DE_CUANDO_SE_INTERCEPTA_AL_PRINCIPIO_LA_REQUEST
};

var apc = new saml2.APConnector(ap_connector_options);

app.post('/wingardium_leviosa',function(req,res) {
    
    var new_attributes = [
        {'saml2:Attribute': {
            "@FriendlyName": "DP", // Esto tiene que ser customizable 
            "@Name": "http://eidas.europa.eu/attributes/naturalperson/DP", // Esto tiene que ser customizable 
            "@NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "saml2:AttributeValue": {
                "@xmlns:eidas-natural": "http://eidas.europa.eu/attributes/naturalperson", // Esto tiene que ser customizable 
                "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance", 
                "@xsi:type": "eidas-natural:DP", // Esto tiene que ser customizable
                '#text': 'DP'
            }
        }},
        {'saml2:Attribute': {
            "@FriendlyName": "VR", // Esto tiene que ser customizable 
            "@Name": "http://eidas.europa.eu/attributes/naturalperson/VR", // Esto tiene que ser customizable 
            "@NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "saml2:AttributeValue": {
                "@xmlns:eidas-natural": "http://eidas.europa.eu/attributes/naturalperson", // Esto tiene que ser customizable 
                "@xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance", 
                "@xsi:type": "eidas-natural:VR", // Esto tiene que ser customizable
                '#text': 'VR'
            }
        }},
    ]

    var options = {
        request_body: req.body,
        new_attributes: new_attributes
    };
    apc.post_assert(idp, options, function(err, saml_response) {
        if (err != null) {
            console.log('------------------------------------ERROR------------------------------------', err);
        } else {
            console.log('------------------------------------ANOTTHAR DAY------------------------------------', saml_response);
        }
    });
});

app.use ('/', proxy(config.eidas_node, {
    proxyReqBodyDecorator: function(proxyReq, srcReq) {
        return new Promise(function(resolve, reject) {

            var json = qs.parse(proxyReq.toString('utf8'));
            // console.log('Body', json);
            var options = {request_body: json};
            sp.post_assert(idp, options, function(err, saml_response) {
                if (err != null) {
                    console.log('ERROR', err);
                        
                } else {
                    var dom = saml_response.decrypted;

                    var ser = new xmldom.XMLSerializer().serializeToString(dom);

                    console.log('string', ser);

                    var assertion_element = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')[0];


                    var attributeStatement = assertion_element.getElementsByTagNameNS(XMLNS.SAML, 'AttributeStatement')[0];

                    var new_element = new xmldom.DOMParser().parseFromString('<saml2:Attribute FriendlyName="PEPE" Name="http://eidas.europa.eu/attributes/naturalperson/PEPE" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="eidas-natural:PEPE">PEPEITO</saml2:AttributeValue></saml2:Attribute>');  

                    attributeStatement.appendChild(new_element);

                    console.log('string nuevo', new xmldom.XMLSerializer().serializeToString(dom));

                    resolve(proxyReq);
                }
            });
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
