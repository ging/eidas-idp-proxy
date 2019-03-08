var sha1 = require('sha1');
var XMLHttpRequest = require('xmlhttprequest').XMLHttpRequest;
var available_attributes = require('./available_attributes.json');

exports.getAttributes = function(id, attributes_list, callback) {
	console.log('Getting attributes for', id);
	var attributes_response = {};

	id = '47289636A';
	var hash = sha1(id);

	var xhr = new XMLHttpRequest();
	var personal_response, academic_response;

	var url = 'https://estudios.etsit.upm.es/etsitAPIRest/persona.php?token=' + hash;
	xhr.open('GET', url, false); 
	xhr.send(null);
	if (xhr.status == 200 && xhr.responseText !== '')
		personal_response = JSON.parse(xhr.responseText)[0];

	url = 'https://estudios.etsit.upm.es/etsitAPIRest/academico.php?token=' + hash;
	xhr.open('GET', url, false); 
	xhr.send(null);
	if (xhr.status == 200 && xhr.responseText !== '')
		academic_response = JSON.parse(xhr.responseText);

	if (personal_response) {
		console.log('Respuesta personal', personal_response);
		for (var a in attributes_list) {
			console.log('I need ', attributes_list[a]);
			var key = available_attributes['persona'][attributes_list[a]];
			if (key) {
				console.log('It is available with key', key);
				var value = personal_response[key];
				if (value) {
					console.log('And it is in the response with value', value);
					attributes_response[attributes_list[a]] = value;
				}

			}
		}
	}
	if (academic_response) {
		console.log('Respuesta academic', academic_response);
		for (var a in attributes_list) {
			console.log('I need ', attributes_list[a]);

			var value = available_attributes['academico'][attributes_list[a]];

			if (value) {
				console.log('It is available with fixed value', value);
				attributes_response[attributes_list[a]] = value;
			} else {
				switch(attributes_list[a]) {
					case "CurrentDegree":
						var lastDegree = academic_response[academic_response.length - 1].nombre;
						attributes_response[attributes_list[a]] = lastDegree;
						break;
					default:
						console.log('not available');
						break;
				}
				
			}

		}
	}
	callback(null, attributes_response);
	
}

