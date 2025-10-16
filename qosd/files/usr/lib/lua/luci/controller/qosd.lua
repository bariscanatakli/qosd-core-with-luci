module("luci.controller.qosd", package.seeall)
function index()
    entry({"admin", "network", "qosd"}, cbi("qosd/qosd_view"), _("QoS Dashboard"), 20)
end
