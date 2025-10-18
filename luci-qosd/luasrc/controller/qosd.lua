-- SPDX-License-Identifier: MIT
-- LuCI controller exposing QoSD dashboards.
-- Combines ubus live snapshot with enriched persona data as per Dong et al. 2019.

module("luci.controller.qosd", package.seeall)

local fs = require "nixio.fs"

function index()
	if not fs.access("/usr/sbin/qosd") then
		return
	end

	entry({"admin", "status", "qosd"}, alias("admin", "status", "qosd", "overview"),
		_("QoSD Personas"), 60).dependent = false

	entry({"admin", "status", "qosd", "overview"},
		template("qosd/status"), _("LAN Personas"), 10).leaf = true

	entry({"admin", "status", "qosd", "live"},
		call("action_live_snapshot")).leaf = true
end

function action_live_snapshot()
	local http = require "luci.http"
	local ubus = require "ubus"
	local conn = ubus.connect()
	if not conn then
		http.status(500, "No ubus")
		http.write_json({ error = "ubus_connect_failed" })
		return
	end

	local res = conn:call("qosd", "live", { limit = 256 }) or {}
	conn:close()

	http.prepare_content("application/json")
	http.write_json(res)
end
