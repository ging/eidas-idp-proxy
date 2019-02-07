// Load external dependencies
const fs = require('fs');
const https = require('https'); 
const async = require('async');
const errorhandler = require('errorhandler');
const proxy = require('express-http-proxy');
const bodyParser = require('body-parser');
const qs = require('querystring');
const xmldom = require('xmldom');
const path = require('path');

// Load custom libraries
const saml2 = require('./lib/saml2.js');
const ap = require('./lib/ap.js');

// Load configuration file
const config = require('./config');

// Load available academic attributes json to generate a new response including parameters obtained from AP
const academic_attributes = require('./lib/academic_attributes.json');

// Config HTTPs
config.https = config.https || {};

// Logs and create application
const log = require('./lib/logger').logger.getLogger("Server");
const express = require('express');
const app = express();

// Exception caught
process.on('uncaughtException', function (err) {
  log.error('Caught exception: ' + err);
});
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";


// Set engine to render consent
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Make public folder visible 
app.use(express.static(path.join(__dirname, 'public')));

// Error handler
app.use(errorhandler({log: log.error}));

// Configure por to listen
let port = config.listen_port || 80;
if (config.https.enabled) {port = config.https.port || 443;}
app.set('port', port);


//////////////////////////////////////////////////
// Create Idp connector with lib/saml2.js 
var idp_options = {
  sso_login_url: '',
  sso_logout_url: "",
  certificates: []
};
var idp = new saml2.IdentityProvider(idp_options);

// Create AP connector with lib/saml2.js 
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
//////////////////////////////////////////////////

// Attributes to identify parameters on saml requests and responses
XMLNS = {
  SAML: 'urn:oasis:names:tc:SAML:2.0:assertion',
  SAMLP: 'urn:oasis:names:tc:SAML:2.0:protocol',
  MD: 'urn:oasis:names:tc:SAML:2.0:metadata',
  DS: 'http://www.w3.org/2000/09/xmldsig#',
  XENC: 'http://www.w3.org/2001/04/xmlenc#',
  EXC_C14N: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  EIDAS: 'http://eidas.europa.eu/saml-extensions'
};

// Attribute mapping to handle requests whose strucutre is:
//  {id: 
//    {
//      attributes: [list of attributes before redirect request to IDP],
//      personIdentifier: user_eID,
//      needed_attributes: [list of attributes to be send to AP],
//      response_validated: [parse response from IdP],
//   }
//  }
var attributes_map = {};


// For requests from eIDAS Node to IdP
app.use ('/IdP', proxy(config.idp, {
    proxyReqBodyDecorator: function(proxyReq, srcReq) {

        return new Promise(function(resolve, reject) {
            if (srcReq.originalUrl === '/IdP/AuthenticateCitizen') {
                console.log("================ IDA ================");
                var json = qs.parse(proxyReq.toString('utf8'));
                var samlreq = json.SAMLRequest;
                var buff = new Buffer(samlreq, 'base64');  
                var text = buff.toString('utf8');
                var xml = new xmldom.DOMParser().parseFromString(text);
                var request_element = xml.getElementsByTagNameNS(XMLNS.SAMLP, 'AuthnRequest')[0];
                var request_id = request_element.getAttribute('ID');
                console.log('IDA - Request ID: ', request_id);
                var extensions_element = request_element.getElementsByTagNameNS(XMLNS.SAMLP, 'Extensions')[0];
                var requested_attributes = extensions_element.getElementsByTagNameNS(XMLNS.EIDAS, 'RequestedAttributes')[0];
                var attributes = requested_attributes.getElementsByTagNameNS(XMLNS.EIDAS, 'RequestedAttribute');
                console.log('IDA - Requested Attributes', attributes.length);

                attributes_map[request_id] = {};
                attributes_map[request_id]['attributes'] = [];

                for (var i = 0; i < attributes.length; i++) {
                    console.log('IDA - Attribute ', attributes[i].getAttribute('FriendlyName'));
                    attributes_map[request_id]['attributes'].push(attributes[i].getAttribute('FriendlyName'));
                }
                console.log('IDA - Requested Attributes Map', attributes_map);


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



// Parse body request
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());


// For requests from IdP to eIDAS Node
app.use('/EidasNode', parse_response, proxy(config.eidas_node, {
    limit: '5mb',
    proxyReqBodyDecorator: function(proxyReq, srcReq) {
        if (srcReq.path === '/IdpResponse') {
            return request_ap_and_reencrypt(srcReq.personIdentifier, srcReq.needed_attributes, srcReq.response_validated, proxyReq);
        } else {
            return new Promise(function (resolve, reject) {
                resolve(proxyReq);
            });
        }
    }, proxyReqPathResolver: function(req) {
        return new Promise(function (resolve, reject) {
            resolve('/EidasNode' + req.url);
        });
    }
}));

// Parse IDP response and render consent view
function parse_response(req, res, next) {
    console.log("================ VUELTA ================");
    // APARECEN MUCHOS VUELTA --> PAR_RES PORQUE SE PIDEN DEPENDENCIAS PARA RENDERIZAR LA PAGINA EN 
    // EL NODO EIDAS. POR ESO SE COMPRUEBA EL PATH "/IdpResponse" PARA QUE SOLO SE PARSEE UNA VEZ 
    console.log("VUELTA --> PAR_RES");
    var json = req.body;
    if (req.path === '/IdpResponse') {
        if (json.consent) {
            req.personIdentifier = attributes_map[json.response_to]['personIdentifier'];
            req.needed_attributes = attributes_map[json.response_to]['needed_attributes'];
            req.response_validated = attributes_map[json.response_to]['response_validated'];

            next();
        } else {
            var options_validate = {
                request_body: json
            };

            return apc.post_assert(idp, options_validate, function(err, response_validated) {

                if (err != null) {
                    console.log("VUELTA --> PAR_RES: Error ", err);
                    // reject(err)                        
                } else {
                    var samlres = json.SAMLResponse;
                    var buff = new Buffer(samlres, 'base64');
                    var text = buff.toString('utf8');
                    var xml = new xmldom.DOMParser().parseFromString(text);

                    var response_element = xml.getElementsByTagNameNS(XMLNS.SAMLP, 'Response')[0];
                    var response_to = response_element.getAttribute('InResponseTo');
                    console.log('VUELTA --> PAR_RES: Requested Attributes Map', attributes_map[response_to]['attributes']);
                    console.log('VUELTA --> PAR_RES: In response to', response_to);
                    var requested_attributes = attributes_map[response_to]['attributes'];
                    console.log('VUELTA --> PAR_RES: Requested attributes: ', requested_attributes);



                    var dom = response_validated.decrypted;
                    var assertion_element = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')[0];
                    var attributeStatement = assertion_element.getElementsByTagNameNS(XMLNS.SAML, 'AttributeStatement')[0];
                    // console.log('string', attributeStatement);
                    // var new_element = new xmldom.DOMParser().parseFromString('<saml2:Attribute FriendlyName="PEPE" Name="http://eidas.europa.eu/attributes/naturalperson/PEPE" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="eidas-natural:PEPE">PEPEITO</saml2:AttributeValue></saml2:Attribute>');  

                    // attributeStatement.appendChild(new_element);

                    var attributes = attributeStatement.getElementsByTagNameNS(XMLNS.SAML, 'Attribute');
                    console.log('VUELTA --> PAR_RES: Received Attributes', attributes.length);

                    var received_attributes = [];

                    var needed_attributes = [];
                    var personIdentifier;

                    for (var i = 0; i < attributes.length; i++) {
                        console.log('VUELTA --> PAR_RES: Attribute ', attributes[i].getAttribute('FriendlyName'));
                        received_attributes.push(attributes[i].getAttribute('FriendlyName'));
                        if (attributes[i].getAttribute('FriendlyName') === 'PersonIdentifier') {
                            var value = attributes[i].getElementsByTagNameNS(XMLNS.SAML, 'AttributeValue')[0];
                            personIdentifier = value.childNodes[0].nodeValue;
                            console.log('VUELTA --> PAR_RES: Personal ID', personIdentifier);
                        };
                    }

                    for (var attr in requested_attributes) {
                        console.log('VUELTA --> PAR_RES: He pedido ', requested_attributes[attr]);
                        if (received_attributes.indexOf(requested_attributes[attr]) === -1) {
                            console.log('VUELTA --> PAR_RES: No me lo han dado');
                            needed_attributes.push(requested_attributes[attr]);
                        };
                    }

                    console.log('VUELTA --> PAR_RES: Necesito pedir al AP', needed_attributes);

                    // SUSTITUIRLO POR LO QUE HAY DENTRO DE needed_attributes
                    let academic_attributes_test = [
                        'HomeInstitutionAddress',
                        'HomeInstitutionCountry',
                        'HomeInstitutionIdentifier'
                    ];
                    let personal_attributes_test = [
                        'Photo',
                        'PhoneNumber'
                    ];
                    //////////////////////////


                    if (academic_attributes_test.length <= 0 && personal_attributes_test.length <= 0) {
                        req.personIdentifier = personIdentifier;
                        req.needed_attributes = needed_attributes;
                        req.response_validated = response_validated;
                        next();
                    } else {
                        attributes_map[response_to]['personIdentifier'] = personIdentifier;
                        attributes_map[response_to]['needed_attributes'] = needed_attributes;
                        attributes_map[response_to]['response_validated'] = response_validated;
                        return res.render('consent', {academic_attributes: academic_attributes_test, personal_attributes: personal_attributes_test, response_to: response_to})
                    }
                }
            });
        }
    } else {
        next();
    }
}

// Request academic attributes to AP after consent and reencrypt response
function request_ap_and_reencrypt(personIdentifier, needed_attributes, response_validated, proxyReq) {
    console.log("VUELTA --> RAP&REEN");
    return new Promise(function(resolve, reject) {
        // If no need_attributes just redirects request
        if (!needed_attributes || needed_attributes.length <= 0) {
            resolve(proxyReq);
        } else {
            // Send request to AP to obtain academic attributes
            return ap.getAttributes(personIdentifier, needed_attributes, function (error, response) {
                if (error) {
                    console.log("VUELTA --> RAP&REEN: Error get attributes ", error);
                    reject(error);
                } else {
                    console.log("VUELTA --> RAP&REEN: AP me devuelve ", response);

                    if (Object.keys(response).length > 0) {
                         var attributes_to_be_included = [];

                        for (var a in response) {
                            var attribute = academic_attributes[a];
                            attribute['saml2:AttributeValue']['#text'] = response[a];
                            attributes_to_be_included.push({'saml2:Attribute': attribute });
                        }

                        console.log("VUELTA --> RAP&REEN: Voy a incluir ", attributes_to_be_included);

                        var options_reencrypt = {
                            saml_response: response_validated.saml_response,
                            decrypted_assertion: response_validated.decrypted,
                            new_attributes: attributes_to_be_included,
                            is_assertion_firmed: response_validated.is_assertion_firmed
                        };

                        return apc.reencrypt_response(idp, options_reencrypt, function(err, saml_response) {
                            if (err != null) {
                                console.log('VUELTA --> RAP&REEN: Error reencrypt ', err);
                                reject(err)
                            } else {
                                console.log('VUELTA --> RAP&REEN: Cifrado conseguido')
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
    })
}

// Check if HTTPs is enabled and run server
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
