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
var ap = require('./lib/ap.js');

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
/*var sp_options = {
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

var sp = new saml2.ServiceProvider(sp_options);
*/

// Create identity provider
var idp_options = {
  sso_login_url: '',
  sso_logout_url: "",
  certificates: []
};
var idp = new saml2.IdentityProvider(idp_options);



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
        // 138.4.7.110 proxyReq.connection.remoteAddress
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

                // Create service provider
                var ap_connector_options = {
                    private_key: fs.readFileSync("cert/node-key.pem").toString(),// fs.readFileSync("cert/mashmetv/mashmetv-key.pem").toString(),
                    certificate: [fs.readFileSync("cert/connector-es.pem").toString()], //fs.readFileSync("cert/mashmetv/mashmetv-cert.pem").toString(),
                    rsa_pub: fs.readFileSync("cert/pubkey-connector.pem").toString() // fs.readFileSync("cert/mashmetv/mashmetv-pubkey.pem").toString()
                };

                var apc = new saml2.APConnector(ap_connector_options);

                //console.log('Body', json);
                var options_validate = {
                    request_body: JSON.parse(proxyReq.toString('utf8')), // VOLVER A CAMBIARLO POR SOLO json
                };
                return apc.post_assert(idp, options_validate, function(err, response_validated) {

                    if (err != null) {
                        console.log('ERROR', err);
                        reject(err)                        
                    } else {
                        var samlres = JSON.parse(proxyReq.toString('utf8')).SAMLResponse; // VOLVER A CAMBIARLO A json.SAMLResponse
                        var buff = new Buffer(samlres, 'base64');
                        var text = buff.toString('utf8');
                        var xml = new xmldom.DOMParser().parseFromString(text);
                        var response_element = xml.getElementsByTagNameNS(XMLNS.SAMLP, 'Response')[0];
                        var response_to = response_element.getAttribute('InResponseTo');
                        console.log('Requested Attributes Map', attributes_map);
                        console.log('In response to', response_to);
                        var requested_attributes = attributes_map[response_to];
                        console.log('Requested attributes: ', requested_attributes);



                        var dom = response_validated.decrypted;
                        var ser = new xmldom.XMLSerializer().serializeToString(dom);
                        var assertion_element = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')[0];
                        var attributeStatement = assertion_element.getElementsByTagNameNS(XMLNS.SAML, 'AttributeStatement')[0];
                        // console.log('string', attributeStatement);
                        // var new_element = new xmldom.DOMParser().parseFromString('<saml2:Attribute FriendlyName="PEPE" Name="http://eidas.europa.eu/attributes/naturalperson/PEPE" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="eidas-natural:PEPE">PEPEITO</saml2:AttributeValue></saml2:Attribute>');  

                        // attributeStatement.appendChild(new_element);

                        var attributes = attributeStatement.getElementsByTagNameNS(XMLNS.SAML, 'Attribute');
                        console.log('Received Attributes', attributes.length);
                        var received_attributes = [];

                        var needed_attributes = [];
                        var personIdentifier;

                        for (var i = 0; i < attributes.length; i++) {
                            console.log('Attribute ', attributes[i].getAttribute('FriendlyName'));
                            received_attributes.push(attributes[i].getAttribute('FriendlyName'));
                            if (attributes[i].getAttribute('FriendlyName') === 'PersonIdentifier') {
                                var value = attributes[i].getElementsByTagNameNS(XMLNS.SAML, 'AttributeValue')[0];
                                personIdentifier = value.childNodes[0].nodeValue;
                                console.log('PERSONAL ID', personIdentifier);
                            };
                        }

                        for (var attr in requested_attributes) {
                            console.log('He pedido ', requested_attributes[attr]);
                            if (received_attributes.indexOf(requested_attributes[attr]) === -1) {
                                console.log('No me lo han dado');
                                needed_attributes.push(requested_attributes[attr]);
                            };
                        }

                        console.log('Necesito pedir al AP', needed_attributes);

                        // PRUEBA
                        personIdentifier = '472789636A'
                        needed_attributes = ['HomeInstitutionAddress',
                                                'HomeInstitutionCountry',
                                                'HomeInstitutionName']


                        return ap.getAttributes(personIdentifier, needed_attributes, function (response, error) {
                            if (error) {
                                console.log("ERROR GET ATRRIBUTES", error)
                                reject(error)
                            } else {
                                console.log('Y me devuelve ', response);

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

                                var options_reencrypt = {
                                    saml_response: response_validated.saml_response,
                                    decrypted_assertion: response_validated.decrypted,
                                    new_attributes: new_attributes
                                };

                                return apc.reencrypt_response(idp, options_reencrypt, function(err, saml_response) {
                                    if (err != null) {
                                        console.log('ERROR', err);
                                        reject(err)
                                    } else {
                                        console.log('**************************CIFRADOOOOOO')
                                        console.log(saml_response)
                                        delete attributes_map[response_to];
                                        let buff = new Buffer(saml_response);
                                        let base64data = buff.toString('base64');
                                        proxyReq.SAMLResponse = base64data;
                                        resolve(proxyReq);
                                    }
                                })
                            }

                        });
                    }
                });
            } else {
                resolve(proxyReq);
            }

        })
        
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
