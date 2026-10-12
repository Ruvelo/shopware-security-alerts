const ApiService = Shopware.Classes.ApiService;

class RuveloSecurityAlertsApiService extends ApiService {
    constructor(httpClient, loginService, apiEndpoint = '_action/ruvelo-security-alerts') {
        super(httpClient, loginService, apiEndpoint);
        this.name = 'ruveloSecurityAlertsApiService';
    }

    findings() {
        return this.httpClient
            .get(`${this.getApiBasePath()}/findings`, { headers: this.getBasicHeaders() })
            .then((response) => ApiService.handleResponse(response));
    }

    check() {
        return this.httpClient
            .post(`${this.getApiBasePath()}/check`, {}, { headers: this.getBasicHeaders(), timeout: 120000 })
            .then((response) => ApiService.handleResponse(response));
    }
}

Shopware.Service().register('ruveloSecurityAlertsApiService', () => {
    return new RuveloSecurityAlertsApiService(
        Shopware.Application.getContainer('init').httpClient,
        Shopware.Service('loginService'),
    );
});
