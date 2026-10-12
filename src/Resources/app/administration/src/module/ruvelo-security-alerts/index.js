import './acl';
import './page/ruvelo-security-alerts-index';
import enGB from './snippet/en-GB.json';
import deDE from './snippet/de-DE.json';

Shopware.Module.register('ruvelo-security-alerts', {
    type: 'plugin',
    name: 'ruvelo-security-alerts',
    title: 'ruvelo-security-alerts.general.title',
    description: 'ruvelo-security-alerts.general.description',
    color: '#3d4eff',
    icon: 'regular-shield',

    snippets: {
        'en-GB': enGB,
        'de-DE': deDE,
    },

    routes: {
        index: {
            component: 'ruvelo-security-alerts-index',
            path: 'index',
            meta: {
                parentPath: 'sw.settings.index.system',
                privilege: 'ruvelo_security_alerts.viewer',
            },
        },
    },

    settingsItem: {
        group: 'system',
        to: 'ruvelo.security.alerts.index',
        icon: 'regular-shield',
        privilege: 'ruvelo_security_alerts.viewer',
    },
});
