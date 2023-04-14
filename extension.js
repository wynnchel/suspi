const vscode = require('vscode');
const axios = require('axios');
const FormData = require('form-data');
const ipaddr = require('ipaddr.js');

const providers = {
	virustotal: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop1')),
		name : "virustotal",
		scan_ignore: false,
		url: true,
		method: "get",
		header: { "x-apikey" : String(vscode.workspace.getConfiguration().get('conf.providers.api.virustotal')) },
		body: "",
		api_mail: "",
		gui_mail: "",
		api_ip: "https://www.virustotal.com/api/v3/ip_addresses/",
		gui_ip: "https://www.virustotal.com/gui/ip-address/",
		api_domain : "https://www.virustotal.com/api/v3/domains/",
		gui_domain: "https://www.virustotal.com/gui/domain/",
		pre_domain: false,
		api_hash: "https://www.virustotal.com/api/v3/files/",
		gui_hash: "https://www.virustotal.com/gui/file/",
		suspicious: "data.data.attributes.last_analysis_stats.suspicous",
		suspicious_treshold : 0,
		malicious: "data.data.attributes.last_analysis_stats.malicious",
		malicious_treshold: 0,
		response_id: "data.data.id"
	},
	inquest: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop2')),
		name : "inquest",
		scan_ignore: false,
		url: true,
		method: "get",
		header: { "Accept" : "application/json" },
		body: "",
		api_mail: "",
		gui_mail: "",
		api_ip: "https://labs.inquest.net/api/iocdb/search?keyword=",
		gui_ip: "https://labs.inquest.net/lookup/ip/",
		api_domain : "https://labs.inquest.net/api/iocdb/search?keyword=",
		gui_domain: "https://labs.inquest.net/lookup/domain/",
		pre_domain: false,
		api_hash: "https://labs.inquest.net/api/iocdb/search?keyword=",
		gui_hash: "https://labs.inquest.net/lookup/hash/",
		suspicious: "data.data.length",
		suspicious_treshold : 0,
		malicious: "data.data.length",
		malicious_treshold: 0,
		response_id: ""
	},
	alienvault: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop3')),
		name : "alienvault",
		scan_ignore: false,
		url: true,
		method: "get",
		header: { "Accept" : "application/json" },
		body: "",
		api_mail: "",
		gui_mail: "",
		api_ip: "https://otx.alienvault.com/api/v1/indicators/IPv4/",
		gui_ip: "https://otx.alienvault.com/indicator/ip/",
		api_domain : "https://otx.alienvault.com/api/v1/indicators/domain/",
		gui_domain: "https://otx.alienvault.com/indicator/domain/",
		pre_domain: false,
		api_hash: "https://otx.alienvault.com/api/v1/indicators/file/",
		gui_hash: "https://otx.alienvault.com/indicator/file/",
		suspicious: "data.pulse_info.count",
		suspicious_treshold : 3,
		malicious: "data.pulse_info.count",
		malicious_treshold: 3,
		response_id: ""
	},
	urlscan: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop4')),
		name : "urlscan",
		scan_ignore: true,
		url: true,
		method: "get",
		header: { "API-Key" : String(vscode.workspace.getConfiguration().get('conf.providers.api.urlscan')) },
		body: "",
		api_mail: "",
		gui_mail: "",
		api_ip: "https://urlscan.io/api/v1/scan/",
		gui_ip: "",
		api_domain : "https://urlscan.io/api/v1/search/?q=domain:",
		gui_domain: "https://urlscan.io/api/v1/result/",
		pre_domain: false,
		api_hash: "",
		gui_hash: "",
		suspicious: "",
		suspicious_treshold : 0,
		malicious: "",
		malicious_treshold: 0,
		response_id: "results.0._id"
	},
	abuseipdb: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop5')),
		name : "abuseipdb",
		scan_ignore: false,
		url: true,
		method: "get",
		header: { "Key" : String(vscode.workspace.getConfiguration().get('conf.providers.api.abuseipdb')) },
		body: "",
		api_mail: "",
		gui_mail: "",
		api_ip: "https://api.abuseipdb.com/api/v2/check?ipAddress=",
		gui_ip: "https://www.abuseipdb.com/check/",
		api_domain : "",
		gui_domain: "",
		pre_domain: false,
		api_hash: "",
		gui_hash: "",
		suspicious: "data.data.abuseConfidenceScore",
		suspicious_treshold : 4,
		malicious: "data.data.abuseConfidenceScore",
		malicious_treshold: 4,
		response_id: ""
	},
	urlahaus: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop6')),
		name : "urlhaus",
		scan_ignore: false,
		url: false,
		method: "post",
		header: { },
		body: "url=$value$",
		api_mail: "",
		gui_mail: "",
		api_ip: "", 
		gui_ip: "",
		api_domain : "https://urlhaus-api.abuse.ch/v1/url/",
		gui_domain: "https://urlhaus.abuse.ch/url/",
		pre_domain: true,
		api_hash: "",
		gui_hash: "",
		suspicious: "data.tags.length",
		suspicious_treshold : 0,
		malicious: "data.tags.length",
		malicious_treshold: 0,
		response_id: "data.id"
	},
	malwarebazaar: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop7')),
		name : "malwarebazaar", 
		scan_ignore: false,
		url: false,
		method: "post",
		header: { },
		body: "query=get_info=hash=$value$",
		api_mail: "",
		gui_mail: "",
		api_ip: "",
		gui_ip: "",
		api_domain : "",
		gui_domain: "",
		pre_domain: false,
		api_hash: "https://mb-api.abuse.ch/api/v1/",
		gui_hash: "https://bazaar.abuse.ch/sample/",
		suspicious : "data.data.length",
		suspicious_treshold : 0,
		malicious: "data.data.length",
		malicious_treshold: 0,
		response_id: "data.data.0.sha256_hash"
	},
	threatfox: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop13')),
		name : "threatfox", 
		scan_ignore: false,
		url: false,
		method: "post",
		header: { },
		body: "",
		api_mail: "",
		gui_mail: "",
		api_ip: "",
		gui_ip: "",
		api_domain : "",
		gui_domain: "",
		pre_domain: "",
		api_hash: "",
		gui_hash: "",
		suspicious : "data.data.length",
		suspicious_treshold : 0,
		malicious: "data.data.length",
		malicious_treshold: 0,
		response_id: "data.data.0.sha256_hash"
	},
	filescan: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop8')),
		name : "filescan",
		scan_ignore: false,
		url: true,
		method: "get",
		header: { "Accept" : "application/json" },
		body: "url=",
		api_mail: "",
		gui_mail: "",
		api_ip: "",
		gui_ip: "",
		api_domain : "",
		gui_domain: "",
		pre_domain: false,
		api_hash: "",
		gui_hash: "",
		suspicious: "",
		suspicious_treshold : 0,
		malicious: "",
		malicious_treshold: 0,
		response_id: ""
	},
	anyrun: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop9')),
		name : "anyrun",
		scan_ignore: false,
		url: true,
		method: "",
		header: { "Accept" : "application/json" },
		body: "url=",
		api_mail: "",
		gui_mail: "",
		api_ip: "",
		gui_ip: "",
		api_domain : "",
		gui_domain: "",
		pre_domain: false,
		api_hash: "",
		gui_hash: "",
		suspicious: "",
		suspicious_treshold : 0,
		malicious: "",
		malicious_treshold: 0,
		response_id: ""
	},
	joesandbox: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop10')),
		name : "joesandbox",
		scan_ignore: false,
		url: true,
		method: "",
		header: { "Accept" : "application/json" },
		body: "url=",
		api_mail: "",
		gui_mail: "",
		api_ip: "",
		gui_ip: "",
		api_domain : "",
		gui_domain: "",
		pre_domain: false,
		api_hash: "",
		gui_hash: "",
		suspicious: "",
		suspicious_treshold : 0,
		malicious: "",
		malicious_treshold: 0,
		response_id: ""
	},
	crtsh: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop11')),
		name : "crt",
		scan_ignore: true,
		url: true,
		method: "",
		header: { "Accept" : "application/json" },
		body: "url=",
		api_mail: "",
		gui_mail: "",
		api_ip: "",
		gui_ip: "https://crt.sh/?q=",
		api_domain : "",
		gui_domain: "https://crt.sh/?q=",
		pre_domain: false,
		api_hash: "",
		gui_hash: "",
		suspicious: "",
		suspicious_treshold : 0,
		malicious: "",
		malicious_treshold: 0,
		response_id: ""
	},
	emailrep: {
		active: Boolean(vscode.workspace.getConfiguration().get('conf.providers.activate.prop12')),
		name : "emailrep",
		scan_ignore: true,
		url: true,
		method: "get",
		header: { "Key" : "application/json" },
		body: "",
		api_mail: "https://emailrep.io/",
		gui_mail: "",
		api_ip: "",
		gui_ip: "",
		api_domain : "",
		gui_domain: "",
		pre_domain: false,
		api_hash: "",
		gui_hash: "",
		suspicious: "data.suspicious",
		suspicious_treshold : true,
		malicious: "data.details.malicious_activity",
		malicious_treshold: true,
		response_id: ""
	}
}

function validate(response, suspicious, suspicious_treshold, malicious, malicious_treshold) {
	if(response.status == "200") {
		if((parseInt(objectPath(response, suspicious))>suspicious_treshold) || (parseInt(objectPath(response, malicious))>malicious_treshold)) {
			return true;
		} else {
			return false;
		}
	} else {
		throw new Error("Custom error message");
	}
}

function unique (array) {
	return [...new Set(array)];
}

function objectPath(obj, path) {
	var paths = path.split('.')
	  , current = obj
	  , i;
  
	for (i = 0; i < paths.length; ++i) {
	  if (current[paths[i]] == undefined) {
		return undefined;
	  } else {
		current = current[paths[i]];
	  }
	}
	return current;
}

function axiosConfig (entry, scan, ioc) {
	// make regex better. include / after tld
	if(entry.url) {
		ioc = ioc.replace(/.+\/\/|www.|:.+|\/.+/gm,'');
		var config = {
			method: entry.method,
			headers: entry.header,
			url: scan + ioc,
			timeout: parseInt(vscode.workspace.getConfiguration().get('conf.providers.request.timeout'))
		};
	} else {
		const content = entry.body.replace("$value$", ioc).split("=");
		var form = new FormData();
		if(content.length>=2) { form.append(content[0], content[1]); }
		if(content.length==4) { form.append(content[2], content[3]) ; }
		var config = {
			method: entry.method,
			maxBodyLength: Infinity,
			data : form,
			url: scan,
			timeout: parseInt(vscode.workspace.getConfiguration().get('conf.providers.request.timeout'))
		};
	}
	if(String(vscode.workspace.getConfiguration().get('conf.proxy.url'))!="") {
		var settings = String(vscode.workspace.getConfiguration().get('conf.proxy.url')).replace("//","").split(":");
		Object.assign(config, {
			proxy: {
				protocol: settings[0],
				host: settings[1],
				port: settings[2],
			  }
			}
			)
	}
	return config;
}

function findIndicators (scan, matches) {
	var promises = {};
	var data = {};

	if(matches) {
		matches.forEach((indicator) => { // aka ip adresses

			promises[indicator] = {};
			data[indicator] = {};

			Object.keys(providers).forEach(property => {
				if((providers[property].active) && ( providers[property]['api_'+scan] != "")) { //provider entry is active
					
					promises[indicator][property] = {};
					data[indicator][property] = {};

					promises[indicator][property] = axios( axiosConfig(providers[property], providers[property]['api_'+scan], indicator ) )
					.then(response => {
						data[indicator][property] = response;
					  });
				}
			});
		});

		Object.keys(promises).forEach(indicator => {
			var list = [];

			Object.keys(promises[indicator]).forEach(function(entry) {	
				list.push(promises[indicator][entry]);
			});

			Promise.all(list)
			.then(result => {
				var claimer = {};
				var counter = 0;
				Object.keys(data[indicator]).forEach(response => {
					if(validate(data[indicator][response], providers[response]["suspicious"], providers[response]["suspicious_treshold"], providers[response]["malicious"], providers[response]["malicious_treshold"])) {
						claimer[response] = providers[response]["gui_"+scan] + indicator.replace(/.+\/\/|www.|:.+|\/.+/gm,'');
					} else {
						counter++;
					}
				});

				Object.keys(claimer).forEach(alerts => {
					vscode.window.showInformationMessage(Object.keys(claimer).length + " of " + (Object.keys(claimer).length + counter) + " Providers found indicators for " + indicator, "show providers sites", "also show additional")
					.then(selection => {
						switch(selection) {
							case "show providers sites":
								Object.keys(claimer).forEach(handler => {
									 vscode.env.openExternal(vscode.Uri.parse(claimer[handler])) 
									} );
								break;
							case "also show additional":
								Object.keys(providers).forEach(provider => {
									if(providers[provider]["gui_"+scan] != "") {
										vscode.env.openExternal(vscode.Uri.parse(providers[provider]["gui_"+scan]+indicator));
									}
								} );
								break;
						}
					});
				});
			

			}).catch((error) => {
				console.error(error);
			  });
		});
	}
}

function exclusion (scan, data) {
	switch (scan) {
		case "ip":
			if(String(vscode.workspace.getConfiguration().get('conf.ipscan.exclude'))) {
				var list = {};
				list["private"] = [];
				String(vscode.workspace.getConfiguration().get('conf.ipscan.exclude')).trim().split(",").forEach(entry => {
					var temp = entry.split("/");
					list["private"].push([ ipaddr.parse(temp[0]), temp[1] ] );
				});
			}

			var new_data = [];
			data.forEach(ip => {
				if(ipaddr.parse(ip).range() != "private" && ipaddr.subnetMatch(ipaddr.parse(ip), list, 'unknown') != "private" ) {
					new_data.push(ip);
				}
			});	
			return new_data;
		case "mail":
			if(String(vscode.workspace.getConfiguration().get('conf.mailscan.exclude'))) {
				var new_data = [];
				data.forEach(mail => {
					var temp = false;
					String(vscode.workspace.getConfiguration().get('conf.mailscan.exclude')).trim().split(",").forEach(entry => {
						if(mail.includes(entry)) {
							temp = true;
						}
					});
					if(!temp) { new_data.push(mail); }
				});
				return new_data;
			} else {
				return data;
			}
		case "domain":
			if(String(vscode.workspace.getConfiguration().get('conf.domainscan.exclude'))) {
				var new_data = [];
				data.forEach(domain => {
					var temp = false;
					String(vscode.workspace.getConfiguration().get('conf.domainscan.exclude')).trim().split(",").forEach(entry => {
						if(domain.includes(entry)) {
							temp = true;
						}
					});
					if(!temp) { new_data.push(domain); }
				});
				return new_data;
			} else {
				return data;
			}
			
	}
}

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {

	let ipscan = vscode.commands.registerCommand('suspi.ipscan', function () {

	const ip_regex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/gm;
	const ip_matches = unique(vscode.window.activeTextEditor.document.getText().match(ip_regex));

	findIndicators("ip",exclusion("ip", ip_matches));
});


	let mailscan = vscode.commands.registerCommand('suspi.mailscan', function() {
		
		vscode.window.showInformationMessage("mailscan isn't active yet");
		
		const mail_regex = /^(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$/gm;
		const mail_matches = unique(vscode.window.activeTextEditor.document.getText().match(mail_regex));

		findIndicators("mail", exclusion("mail", mail_matches));
	});

	let domainscan = vscode.commands.registerCommand('suspi.domainscan', function() {

		const domain_regex = /(http|https)?:\/\/(\S+[a-zA-Z])/gm;
		const domain_matches = unique(vscode.window.activeTextEditor.document.getText().match(domain_regex));
		
		findIndicators("domain",domain_matches);
	});

	let hashscan = vscode.commands.registerCommand('suspi.hashscan', function() {
		
		const hash_regex = /^[a-zA-Z0-9]{32,64}$/gm;
		const hash_matches = unique(vscode.window.activeTextEditor.document.getText().match(hash_regex));
		
		findIndicators("hash",hash_matches);
		
	});
	
	context.subscriptions.push(ipscan);
	context.subscriptions.push(mailscan);
	context.subscriptions.push(domainscan);
	context.subscriptions.push(hashscan);
}

function deactivate() {}

module.exports = {
	activate,
	deactivate
}