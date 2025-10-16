'use strict';
'require view';
'require ui';
'require rpc';
'require poll';
'require dom';

const callLive = rpc.declare({
	object: 'qosd',
	method: 'live',
	params: [ 'limit' ],
	expect: { '': {} }
});

return view.extend({
	load: function() {
		return Promise.resolve();
	},

	render: function() {
		const root = E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('QoS Dashboard - Live Traffic')),
			E('p', {}, _('Active clients, refreshed every 2 seconds.')),
			E('div', { id: 'qosd-live-table' }, _('Loading...'))
		]);

		const fmtbps = (v) => {
			if (!v)
				return '0';

			if (v >= 1e9)
				return (v / 1e9).toFixed(2) + ' Gbps';

			if (v >= 1e6)
				return (v / 1e6).toFixed(1) + ' Mbps';

			if (v >= 1e3)
				return (v / 1e3).toFixed(0) + ' kbps';

			return String(v) + ' bps';
		};

		const badge = (value, palette) => {
			if (!value)
				return E('span', {}, '-');

			const key = String(value).toLowerCase();
			const color = palette[key] || '#607d8b';

			return E('span', {
				style: 'display:inline-block;padding:2px 8px;border-radius:12px;' +
					'background:' + color + ';color:#fff;font-size:90%;text-transform:capitalize;'
			}, value);
		};

		const categoryPalette = {
			streaming: '#4caf50',
			gaming: '#3f51b5',
			voip: '#8e24aa',
			work: '#009688',
			bulk: '#ff9800',
			iot: '#795548',
			latency: '#2196f3',
			other: '#607d8b'
		};

		const priorityPalette = {
			high: '#e53935',
			medium: '#fb8c00',
			low: '#43a047'
		};

		const update = () => callLive(50).then(res => {
			const container = document.getElementById('qosd-live-table');
			if (!container)
				return;

			const rows = (res.hosts || []).map(h => E('tr', {}, [
				E('td', {}, h.hostname || h.ip || '-'),
				E('td', {}, h.ip || '-'),
				E('td', {}, h.mac || '-'),
				E('td', {}, badge(h.persona || h.category, categoryPalette)),
				E('td', {}, badge(h.priority, priorityPalette)),
				E('td', {}, h.policy_action || '-'),
				E('td', {}, h.dscp || '-'),
				E('td', {}, (h.confidence != null) ? (h.confidence + ' %') : '-'),
				E('td', { style: 'text-align:right' }, fmtbps(h.rx_bps || 0)),
				E('td', { style: 'text-align:right' }, fmtbps(h.tx_bps || 0)),
				E('td', {}, h.last_seen ? new Date(h.last_seen * 1000).toLocaleTimeString() : '-')
			]));

			const table = E('table', { 'class': 'table cbi-section-table' }, [
				E('tr', {}, [
					E('th', {}, _('Host')),
					E('th', {}, _('IP')),
					E('th', {}, _('MAC')),
					E('th', {}, _('Persona')),
					E('th', {}, _('Priority')),
					E('th', {}, _('Policy')),
					E('th', {}, _('DSCP')),
					E('th', {}, _('Confidence')),
					E('th', {}, _('RX (bps)')),
					E('th', {}, _('TX (bps)')),
					E('th', {}, _('Last seen'))
				]),
				...rows
			]);

			dom.content(container, table);
		}).catch(err => {
			const container = document.getElementById('qosd-live-table');
			if (!container)
				return;

			dom.content(container,
				E('div', { 'class': 'alert-message warning' },
					_('QoSD live error: ') + ((err && err.message) ? err.message : String(err))));
		});

		poll.add(update, 2);
		update();

		return root;
	}
});
