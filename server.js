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

var academic_attributes = require('./lib/academic_attributes.json');

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

app.use ('/IdP', proxy(config.idp, {
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


                // Create service provider
                var sp_options = {
                    entity_id: "https://"+config.eidas_node,
                    private_key: fs.readFileSync("cert/mashmetv/mashmetv-key.pem").toString(),
                    certificate: fs.readFileSync("cert/mashmetv/mashmetv-cert.pem").toString(),
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
                
                var new_issuer = 'https://idm-cef-fiware.dit.upm.es/idm/applications/mashmetv/saml2/metadata'

                var resigned_authn_request = sp.refirm_authn_request(samlreq, new_issuer);

                console.log("==================================")
                console.log(resigned_authn_request)

                json.SAMLRequest = resigned_authn_request;
                var json_string = qs.stringify(json)
                var buffer_response = new Buffer(json_string);

                resolve(buffer_response);
            } else {
                resolve(proxyReq);
            }
        })
        
    }, proxyReqPathResolver: function(req) {
        return new Promise(function (resolve, reject) {
            resolve('/IdP' + req.url);
        });
    }
}));


app.use ('/EidasNode', proxy(config.eidas_node, {
    limit: '5mb',
    proxyReqBodyDecorator: function(proxyReq, srcReq) {

        return new Promise(function(resolve, reject) {
            if (srcReq.originalUrl === '/EidasNode/IdpResponse') {
                if (srcReq.connection.remoteAddress === '::ffff:138.4.7.110') {
                    resolve(proxyReq);
                } else {
                    console.log('**************************VUELTAAAAAAAAAAAAAAAAAAAAAAAAAAA');

                    var json = qs.parse(proxyReq.toString('utf8'));

                    // Create service provider
                    var ap_connector_options = {
                        node_private_key: fs.readFileSync("cert/mashmetv/mashmetv-key.pem").toString(),
                        node_certificate: [fs.readFileSync("cert/node_eidas_certificate.pem").toString()],
                        node_rsa_pub: fs.readFileSync("cert/node_eidas_pubkey.pem").toString(),
                        ap_connector_cert: fs.readFileSync("cert/idp-cert.pem").toString(),
                        ap_connector_key: fs.readFileSync("cert/idp-key.pem").toString(),
                        ignore_timing: true, // ESTO HAY QUE QUITARLO PARA QUE SE TENGA EN CUENTA EL NOTBEFORE Y EL NOTYET
                        ignore_audiences: true, // ESTO HAY QUE QUITARLO TAMBIEN
                        audiences: null, // ESTO HAY QUE QUITARLO PARA QUE SE TENGA EN CUENTA LAS AUDIENCES
                        ignore_signature: false
                    };

                    var apc = new saml2.APConnector(ap_connector_options);

                    //console.log('Body', json);
                    var options_validate = {
                        request_body: json
                    };
                    return apc.post_assert(idp, options_validate, function(err, response_validated) {

                        if (err != null) {
                            console.log('ERROR', err);
                            reject(err)                        
                        } else {
                            var samlres = json.SAMLResponse;
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

                            return ap.getAttributes(personIdentifier, needed_attributes, function (error, response) {
                                if (error) {
                                    console.log("ERROR GET ATRRIBUTES", error)
                                    reject(error)
                                } else {
                                    console.log('Y me devuelve ', response);

                                    if (Object.keys(response).length > 0) {
                                         var attributes_to_be_included = [];

                                        for (var a in response) {
                                            var attribute = academic_attributes[a];
                                            attribute['saml2:AttributeValue']['#text'] = response[a];
                                            attributes_to_be_included.push({'saml2:Attribute': attribute });
                                        }

                                        console.log('VOY A INCLUIR ', attributes_to_be_included);

                                        var options_reencrypt = {
                                            saml_response: response_validated.saml_response,
                                            decrypted_assertion: response_validated.decrypted,
                                            new_attributes: attributes_to_be_included,
                                            is_assertion_firmed: response_validated.is_assertion_firmed
                                        };

                                        return apc.reencrypt_response(idp, options_reencrypt, function(err, saml_response) {
                                            if (err != null) {
                                                console.log('ERROR', err);
                                                reject(err)
                                            } else {
                                                console.log('**************************CIFRADOOOOOO')
                                                delete attributes_map[response_to];
                                                let buff = new Buffer(saml_response);
                                                let base64data = buff.toString('base64');
                                                json.SAMLResponse = base64data;
                                                var json_string = qs.stringify(json)
                                                var buffer_response = new Buffer(json_string);

                                                resolve(buffer_response);
                                            }
                                        })
                                    } else {
                                        resolve(proxyReq);
                                    }
                                }
                            });
                        }
                    });
                }
            } else {
                resolve(proxyReq);
            } 
        })
    }, proxyReqPathResolver: function(req) {
        return new Promise(function (resolve, reject) {
            resolve('/EidasNode' + req.url);
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
