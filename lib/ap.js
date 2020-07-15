
var sha1 = require('sha1');
var XMLHttpRequest = require('xmlhttprequest').XMLHttpRequest;
var available_attributes = require('./available_attributes.json');

exports.getAttributes = function(id, attributes_list, callback) {
	console.log('Getting attributes for', id);
	var attributes_response = {};
	var hash = sha1(id);

	var xhr = new XMLHttpRequest();
	var funcional_diversity_response

	var url = 'http://localhost:5000/users?token=' + hash;
	xhr.open('GET', url, false);
	xhr.send(null);
	if (xhr.status == 200 && xhr.responseText !== '')
		personal_response = JSON.parse(xhr.responseText)[0];

	// if (personal_response) {
	// 	console.log('Respuesta personal', personal_response);
	// 	for (var a in attributes_list) {
	// 		console.log('I need ', attributes_list[a]);
	// 		var key = available_attributes['persona'][attributes_list[a]];
	// 		if (key) {
	// 			console.log('It is available with key', key);
	// 			var value = personal_response[key];
	// 			if (value) {
	// 				console.log('And it is in the response with value', value);
	// 				if (key === 'sexo' && value === 'H') value = 'Male';
	// 				if (key === 'sexo' && value === 'M') value = 'Female';
	// 				if (key === 'sexo' && value === 'D') value = 'Female';
	// 				if (key === 'pais') value = 'ES';
	// 				if (key === 'fecha_nacimiento') {
	// 					value = value.split(' ')[0].split('/').reverse().join('-');
	// 				};
	// 				// if (key === 'pais' && value === 'ESLOVENIA') value = 'SI';
	// 				// if (key === 'pais' && value === 'ITALIA') value = 'IT';
	// 				// if (key === 'pais' && value === 'AUSTRIA') value = 'AT';
	// 				// if (key === 'pais' && value === 'PORTUGAL') value = 'PT';
	// 				attributes_response[attributes_list[a]] = value;
	// 			}

	// 		}
	// 	}
	// }

	callback(null, funcional_diversity_response);
	
}

