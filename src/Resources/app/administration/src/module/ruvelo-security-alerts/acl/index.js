Shopware.Service('privileges').addPrivilegeMappingEntry({
    category: 'permissions',
    parent: 'settings',
    key: 'ruvelo_security_alerts',
    roles: {
        viewer: {
            privileges: ['ruvelo_security_alerts:read'],
            dependencies: [],
        },
        editor: {
            privileges: ['ruvelo_security_alerts:check'],
            dependencies: ['ruvelo_security_alerts.viewer'],
        },
    },
});
