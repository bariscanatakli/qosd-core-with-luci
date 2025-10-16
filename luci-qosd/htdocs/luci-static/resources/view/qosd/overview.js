"use strict";
"require view";
"require rpc";
"require ui";
"require dom";
"require uci";

var callClassify = function (payload) {
	return rpc.call("qosd", "classify", payload || {});
};

var callServiceRestart = rpc.declare({
	object: "service",
	method: "restart",
	params: ["name"],
	expect: { result: "" }
});

return view.extend({
	load: function () {
		return uci.load("qosd");
	},

	toggleSyslogFields: function () {
		var enabled = document.getElementById("syslog_remote").checked;
		["syslog_host", "syslog_port", "syslog_proto"].forEach(function (id) {
			var el = document.getElementById(id);
			if (el)
				el.disabled = !enabled;
		});
	},

	handleSyslogSave: function (ev) {
		ev.preventDefault();

		var remote = document.getElementById("syslog_remote").checked;
		var host = document.getElementById("syslog_host").value.trim();
		var portVal = document.getElementById("syslog_port").value.trim();
		var proto = document.getElementById("syslog_proto").value;
		var level = document.getElementById("syslog_level").value.trim();

		if (remote && host === "") {
			ui.addNotification(null, E("p", {}, _("Remote log host is required when forwarding is enabled.")), "danger");
			return;
		}

		var portNum = parseInt(portVal, 10);
		if (remote && (isNaN(portNum) || portNum < 1 || portNum > 65535)) {
			ui.addNotification(null, E("p", {}, _("Port must be between 1 and 65535.")), "danger");
			return;
		}

		uci.set("qosd", "main", "syslog_remote", remote ? "1" : "0");
		uci.set("qosd", "main", "syslog_host", host);
		uci.set("qosd", "main", "syslog_port", remote ? String(portNum || 5514) : (portVal || ""));
		uci.set("qosd", "main", "syslog_proto", proto);
		uci.set("qosd", "main", "syslog_level", level);

		ui.addNotification(null, E("p", {}, _("Saving syslog settings…")), "info");

		uci.save()
			.then(function () {
				return uci.apply({ rollback: false, timeout: 5, config: ["qosd"] });
			})
			.then(function () {
				return callServiceRestart("qosd");
			})
			.then(function () {
				return callServiceRestart("log");
			})
			.then(function () {
				ui.addNotification(null, E("p", {}, _("Syslog forwarding settings updated.")), "info");
			})
			.catch(function (err) {
				ui.addNotification(null, E("p", {}, _("Failed to apply settings: ") + err), "danger");
			});
	},

	handleClassify: function (ev) {
		ev.preventDefault();

		var src = document.getElementById("src").value.trim();
		var dst = document.getElementById("dst").value.trim();
		var proto = document.getElementById("proto").value.trim();
		var srcPortVal = document.getElementById("src_port").value.trim();
		var dstPortVal = document.getElementById("dst_port").value.trim();
		var hostname = document.getElementById("hostname").value.trim();
		var serviceHint = document.getElementById("service_hint").value.trim();
		var dnsName = document.getElementById("dns_name").value.trim();
		var appHint = document.getElementById("app_hint").value.trim();
		var bytesVal = document.getElementById("bytes_total").value.trim();
		var latencyVal = document.getElementById("latency_ms").value.trim();

		document.getElementById("result").innerHTML = "<em>Testing...</em>";

		var payload = {
			src: src,
			dst: dst,
			proto: proto
		};

		var srcPort = parseInt(srcPortVal, 10);
		if (!isNaN(srcPort) && srcPort > 0)
			payload.src_port = srcPort;

		var dstPort = parseInt(dstPortVal, 10);
		if (!isNaN(dstPort) && dstPort > 0)
			payload.dst_port = dstPort;

		if (hostname)
			payload.hostname = hostname;
		if (serviceHint)
			payload.service_hint = serviceHint;
		if (dnsName)
			payload.dns_name = dnsName;
		if (appHint)
			payload.app_hint = appHint;

		var bytesTotal = parseInt(bytesVal, 10);
		if (!isNaN(bytesTotal) && bytesTotal >= 0)
			payload.bytes_total = bytesTotal;

		var latencyMs = parseInt(latencyVal, 10);
		if (!isNaN(latencyMs) && latencyMs >= 0)
			payload.latency_ms = latencyMs;

		callClassify(payload).then(function (res) {
			var persona = res.persona || res.category || "unknown";
			var priority = res.priority || "normal";
			var policy = res.policy_action || "observe";
			var dscp = res.dscp || "CS0";
			var confidence = (res.confidence != null) ? res.confidence : 0;

			var palette = {
				streaming: "#4CAF50",
				gaming: "#2196F3",
				voip: "#9C27B0",
				work: "#009688",
				bulk: "#FF5722",
				iot: "#795548",
				latency: "#3F51B5",
				other: "#9E9E9E"
			};

			var key = String(persona).toLowerCase();
			var color = palette[key] || "#607D8B";

			var pr = (priority === "high") ? 90 :
				(priority === "medium") ? 60 :
					(priority === "low") ? 30 : 50;

			var card = `
				<div style="border:2px solid ${color}; border-radius:12px; padding:12px; background:#f8f8f8; margin-top:10px;">
					<h3 style="color:${color}; margin:0 0 8px 0;">${_("Classification Result")}</h3>
					<p><b>${_("Persona")}:</b> ${persona}</p>
					<p><b>${_("Priority")}:</b> ${priority}</p>
					<p><b>${_("Policy")}:</b> ${policy}</p>
					<p><b>${_("DSCP Mark")}:</b> ${dscp}</p>
					<p><b>${_("Confidence")}:</b> ${confidence}%</p>
					<div style="background:#ddd; border-radius:8px; height:8px; width:100%;">
						<div style="background:${color}; width:${pr}%; height:8px; border-radius:8px;"></div>
					</div>
				</div>
			`;

			document.getElementById("result").innerHTML = card;
			ui.addNotification(null, E("p", {}, _("QoS classification successful.")), "info");
		}).catch(function (err) {
			document.getElementById("result").innerHTML = '<span style="color:red;">' + _("UBus call failed: ") + err + "</span>";
			ui.addNotification(null, E("p", {}, _("UBus call failed: ") + err), "danger");
		});
	},

	render: function () {
		var remoteEnabled = uci.get("qosd", "main", "syslog_remote") === "1";
		var host = uci.get("qosd", "main", "syslog_host") || "";
		var port = uci.get("qosd", "main", "syslog_port") || "5514";
		var proto = uci.get("qosd", "main", "syslog_proto") || "udp";
		var level = uci.get("qosd", "main", "syslog_level") || "7";

		var remoteToggle = E("input", {
			type: "checkbox",
			id: "syslog_remote",
			change: ui.createHandlerFn(this, "toggleSyslogFields")
		});
		remoteToggle.checked = remoteEnabled;

		var hostInput = E("input", {
			id: "syslog_host",
			class: "cbi-input-text",
			value: host,
			placeholder: _("e.g. 192.168.1.10")
		});

		var portInput = E("input", {
			id: "syslog_port",
			class: "cbi-input-text",
			type: "number",
			min: "1",
			max: "65535",
			value: port
		});

		var protoSelect = E("select", {
			id: "syslog_proto",
			class: "cbi-input-select"
		}, [
			E("option", { value: "udp", selected: proto === "udp" ? "selected" : null }, "UDP"),
			E("option", { value: "tcp", selected: proto === "tcp" ? "selected" : null }, "TCP")
		]);

		var levelInput = E("input", {
			id: "syslog_level",
			class: "cbi-input-text",
			type: "number",
			min: "0",
			max: "8",
			value: level
		});

		hostInput.disabled = !remoteEnabled;
		portInput.disabled = !remoteEnabled;
		protoSelect.disabled = !remoteEnabled;

		var syslogSection = E("div", { "class": "cbi-section" }, [
			E("h2", {}, _("Remote Telemetry Export")),
			E("p", {}, _("Configure where QoSD sends structured logs (Fluent Bit / Fluentd).")),

			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "syslog_remote", "class": "cbi-value-title" }, _("Enable remote forwarding")),
				E("div", { "class": "cbi-value-field" }, remoteToggle)
			]),

			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "syslog_host", "class": "cbi-value-title" }, _("Remote host")),
				E("div", { "class": "cbi-value-field" }, hostInput)
			]),

			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "syslog_port", "class": "cbi-value-title" }, _("Remote port")),
				E("div", { "class": "cbi-value-field" }, portInput)
			]),

			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "syslog_proto", "class": "cbi-value-title" }, _("Protocol")),
				E("div", { "class": "cbi-value-field" }, protoSelect)
			]),

			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "syslog_level", "class": "cbi-value-title" }, _("Log level (0-8)")),
				E("div", { "class": "cbi-value-field" }, levelInput)
			]),

			E("div", { "class": "cbi-value" }, [
				E("button", {
					"class": "btn cbi-button cbi-button-save",
					"click": ui.createHandlerFn(this, "handleSyslogSave")
				}, _("Save"))
			])
		]);

		var classificationSection = E("div", { "class": "cbi-section" }, [
			E("h2", {}, _("QoS Classifier Test")),
			E("p", {}, _("Send a sample ubus call to verify policy decisions.")),

				E("div", { "class": "cbi-value" }, [
					E("label", { "for": "src", "class": "cbi-value-title" }, _("Source IP")),
					E("div", { "class": "cbi-value-field" },
						E("input", { "id": "src", "class": "cbi-input-text", "value": "10.10.1.5" }))
				]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "src_port", "class": "cbi-value-title" }, _("Source port")),
				E("div", { "class": "cbi-value-field" },
					E("input", { "id": "src_port", "class": "cbi-input-text", "type": "number", "min": "0", "max": "65535", "placeholder": _("Optional") }))
			]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "dst", "class": "cbi-value-title" }, _("Destination IP")),
				E("div", { "class": "cbi-value-field" },
					E("input", { "id": "dst", "class": "cbi-input-text", "value": "8.8.8.8" }))
			]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "dst_port", "class": "cbi-value-title" }, _("Destination port")),
				E("div", { "class": "cbi-value-field" },
					E("input", { "id": "dst_port", "class": "cbi-input-text", "type": "number", "min": "0", "max": "65535", "placeholder": _("Optional") }))
			]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "proto", "class": "cbi-value-title" }, _("Protocol")),
				E("div", { "class": "cbi-value-field" },
					E("select", { "id": "proto", "class": "cbi-input-select" }, [
						E("option", { "value": "udp", "selected": "selected" }, "UDP"),
						E("option", { "value": "tcp" }, "TCP")
					]))
			]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "hostname", "class": "cbi-value-title" }, _("Client hostname")),
				E("div", { "class": "cbi-value-field" },
					E("input", { "id": "hostname", "class": "cbi-input-text", "placeholder": _("Optional") }))
			]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "service_hint", "class": "cbi-value-title" }, _("Service hint")),
				E("div", { "class": "cbi-value-field" },
					E("input", { "id": "service_hint", "class": "cbi-input-text", "placeholder": _("e.g. netflix, zoom") }))
			]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "dns_name", "class": "cbi-value-title" }, _("DNS name")),
				E("div", { "class": "cbi-value-field" },
					E("input", { "id": "dns_name", "class": "cbi-input-text", "placeholder": _("Optional") }))
			]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "app_hint", "class": "cbi-value-title" }, _("Application hint")),
				E("div", { "class": "cbi-value-field" },
					E("input", { "id": "app_hint", "class": "cbi-input-text", "placeholder": _("e.g. critical") }))
			]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "bytes_total", "class": "cbi-value-title" }, _("Observed bytes total")),
				E("div", { "class": "cbi-value-field" },
					E("input", { "id": "bytes_total", "class": "cbi-input-text", "type": "number", "min": "0", "placeholder": _("Optional") }))
			]),
			E("div", { "class": "cbi-value" }, [
				E("label", { "for": "latency_ms", "class": "cbi-value-title" }, _("Latency (ms)")),
				E("div", { "class": "cbi-value-field" },
					E("input", { "id": "latency_ms", "class": "cbi-input-text", "type": "number", "min": "0", "placeholder": _("Optional") }))
			]),
			E("div", { "class": "cbi-value" }, [
				E("button", {
					"class": "btn cbi-button cbi-button-apply",
					"click": ui.createHandlerFn(this, "handleClassify")
				}, _("Classify"))
			]),
			E("div", { "id": "result", "style": "margin-top:20px;" })
		]);

		return E("div", { "class": "cbi-map", "style": "max-width:700px; margin:auto;" }, [
			syslogSection,
			classificationSection
		]);
	}
});
