import template from './ruvelo-security-alerts-index.html.twig';
import './ruvelo-security-alerts-index.scss';

const { Component, Mixin } = Shopware;

Component.register('ruvelo-security-alerts-index', {
    template,

    inject: ['ruveloSecurityAlertsApiService', 'acl'],

    mixins: [Mixin.getByName('notification')],

    data() {
        return {
            isLoading: true,
            isChecking: false,
            findings: [],
            notChecked: [],
            lastCheck: null,
        };
    },

    metaInfo() {
        return { title: this.$createTitle() };
    },

    computed: {
        columns() {
            return [
                { property: 'package', label: 'ruvelo-security-alerts.columns.package', primary: true, width: '280px' },
                { property: 'installed', label: 'ruvelo-security-alerts.columns.installed', width: '100px' },
                { property: 'title', label: 'ruvelo-security-alerts.columns.advisory' },
                { property: 'severity_label', label: 'ruvelo-security-alerts.columns.severity', width: '110px' },
                { property: 'fixed_in', label: 'ruvelo-security-alerts.columns.fixedIn', width: '130px' },
            ];
        },

        exploitedCount() {
            return this.findings.filter((finding) => finding.exploited).length;
        },

        neverChecked() {
            return this.lastCheck === null;
        },

        incomplete() {
            return this.lastCheck !== null && !this.lastCheck.complete;
        },

        canCheck() {
            return this.acl.can('ruvelo_security_alerts.editor');
        },
    },

    created() {
        this.load();
    },

    methods: {
        apply(data) {
            this.findings = data.findings;
            this.notChecked = data.not_checked;
            this.lastCheck = data.last_check;
        },

        load() {
            this.isLoading = true;
            return this.ruveloSecurityAlertsApiService
                .findings()
                .then((data) => this.apply(data))
                .catch(() => {
                    this.createNotificationError({ message: this.$tc('ruvelo-security-alerts.messages.loadFailed') });
                })
                .finally(() => {
                    this.isLoading = false;
                });
        },

        checkNow() {
            this.isChecking = true;
            return this.ruveloSecurityAlertsApiService
                .check()
                .then((data) => {
                    this.apply(data);
                    this.createNotificationSuccess({ message: this.$tc('ruvelo-security-alerts.messages.checked') });
                })
                .catch(() => {
                    this.createNotificationError({ message: this.$tc('ruvelo-security-alerts.messages.checkFailed') });
                })
                .finally(() => {
                    this.isChecking = false;
                });
        },
    },
});
